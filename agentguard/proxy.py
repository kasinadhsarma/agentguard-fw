"""FastAPI proxy exposing the firewall over HTTP.

An agent framework calls these endpoints around every tool call:

  POST /sessions                      open a session with the user's request
  POST /sessions/{id}/ingest          label and scan content before the model sees it
  POST /sessions/{id}/model-output    record text the model wrote (keeps taint)
  POST /sessions/{id}/authorize       ask whether a tool call may run
  GET  /sessions/{id}/audit           read the session's audit trail
  POST /tools                         register tool definitions (schemas, profiles)
  GET  /tools                         list the profiles in force
  GET  /audit/verify                  check the hash chain of the audit log
  GET  /audit/export                  export audit log records
  GET  /health                        liveness and which protections are on
  GET  /ready                         readiness: 503 when the store is down
  GET  /metrics                       Prometheus metrics (needs the API key)

Protections (see settings.py):

  * only GET and POST are accepted, everything else is a 405
  * API key authentication when AGENTGUARD_API_KEYS is set (401)
  * per-caller token-bucket rate limit (429 with Retry-After)
  * idle sessions expire (404 afterwards)
  * a shared store that cannot be reached means 503, never a guessed verdict
  * a session holds at most MAX_ITEMS items (413 beyond that)
"""

from __future__ import annotations

import hashlib
import hmac
import time
from contextlib import asynccontextmanager, contextmanager
from typing import Any, Iterator

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .firewall import Firewall
from .metrics import Metrics
from .ratelimit import TokenBucketLimiter
from .sessions import SessionFull, StoreUnavailable
from .settings import ProxySettings, build_stack


ALLOWED_METHODS = ('GET', 'POST')

# this path stays open so load balancers can probe it
OPEN_PATHS = frozenset({'/health', '/ready'})

MAX_EXPORT_RECORDS = 10_000


class SessionRequest(BaseModel):
    """Body for opening a session."""

    model_config = ConfigDict(extra='forbid')

    user_prompt: str = Field(default='', max_length=20000)


class IngestRequest(BaseModel):
    """Body for labeling and scanning a piece of content."""

    model_config = ConfigDict(extra='forbid')

    text: str = Field(max_length=200000)
    source: str = Field(min_length=1, max_length=200)
    sensitive: bool | None = None


class CheckOutputRequest(BaseModel):
    """Body for checking the final answer before it is shown."""

    model_config = ConfigDict(extra='forbid')

    text: str = Field(max_length=200_000)


class ModelOutputRequest(BaseModel):
    """Body for recording text the model produced."""

    model_config = ConfigDict(extra='forbid')

    text: str = Field(max_length=200000)


class AuthorizeRequest(BaseModel):
    """Body for asking whether a tool call may run."""

    model_config = ConfigDict(extra='forbid')

    tool: str = Field(min_length=1, max_length=100)
    args: dict[str, Any] = Field(default_factory=dict)


class ToolsRequest(BaseModel):
    """Body for registering tool definitions."""

    model_config = ConfigDict(extra='forbid')

    tools: list[dict[str, Any]] = Field(min_length=1, max_length=200)


def _digest(value: str) -> bytes:
    """Hash a key so comparisons take the same time for any length."""
    return hashlib.sha256(value.encode()).digest()


def _request_key(request: Request) -> str:
    """Read the caller's key from X-API-Key or a Bearer token."""
    key = request.headers.get('x-api-key', '')
    if not key:
        auth = request.headers.get('authorization', '')
        if auth.lower().startswith('bearer '):
            key = auth[7:].strip()
    return key


def _key_is_valid(candidate: str, keys: frozenset[str]) -> bool:
    """Compare against every key in constant time."""
    wanted = _digest(candidate)
    matched = False
    for key in keys:
        if hmac.compare_digest(wanted, _digest(key)):
            matched = True
    return matched


def _rejection(status: int, detail: str, headers: dict[str, str]) -> JSONResponse:
    """Build a JSON error response."""
    return JSONResponse(
        status_code=status,
        content={'detail': detail},
        headers=headers,
    )


@contextmanager
def _session_scope() -> Iterator[None]:
    """Turn a missing or expired session into a 404."""
    try:
        yield
    except KeyError:
        raise HTTPException(status_code=404, detail='unknown session')


def create_app(
    firewall: Firewall | None = None,
    settings: ProxySettings | None = None,
    limiter: Any = None,
    metrics: Metrics | None = None,
) -> FastAPI:
    """Build the FastAPI app around a firewall instance."""
    guard = firewall or Firewall()
    config = settings or ProxySettings()
    stats = metrics or Metrics()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """On shutdown, hand buffered metrics to Redis so none are lost."""
        yield
        flush = getattr(stats, 'flush', None)
        if flush is not None:
            try:
                await run_in_threadpool(flush)
            except Exception:
                pass

    app = FastAPI(title='AgentGuard', version='0.5.0', lifespan=lifespan)

    if limiter is None and config.rate_limit_per_minute:
        limiter = TokenBucketLimiter(
            per_minute=config.rate_limit_per_minute,
            burst=config.rate_limit_burst,
        )

    @app.exception_handler(StoreUnavailable)
    async def store_down(request: Request, error: StoreUnavailable):
        """The shared store is unreachable: fail closed."""
        return _rejection(503, 'Session store unavailable', {'Retry-After': '1'})

    @app.exception_handler(SessionFull)
    async def session_full(request: Request, error: SessionFull):
        """The session holds as many items as it may."""
        return _rejection(413, 'Session item limit reached', {})

    async def _gate(request: Request) -> JSONResponse | None:
        """Apply method, authentication and rate-limit checks in order.

        Returns a rejection, or None when the request may proceed.
        """
        if request.method not in ALLOWED_METHODS:
            return _rejection(
                405,
                'Method Not Allowed',
                {'Allow': ', '.join(ALLOWED_METHODS)},
            )

        if request.url.path in OPEN_PATHS:
            return None

        client = request.client.host if request.client else 'unknown'
        identity = 'ip:' + client

        async def spend(who: str) -> tuple[bool, float]:
            """Take a token; a network-backed limiter runs off the loop."""
            if getattr(limiter, 'blocking', False):
                return await run_in_threadpool(limiter.check, who)
            return limiter.check(who)

        try:
            if config.api_keys:
                key = _request_key(request)
                if not _key_is_valid(key, config.api_keys):
                    # failed attempts still cost the caller a token
                    if limiter is not None:
                        allowed, wait = await spend(identity)
                        if not allowed:
                            return _rejection(
                                429,
                                'Too Many Requests',
                                {'Retry-After': str(int(wait) + 1)},
                            )
                    return _rejection(
                        401,
                        'Unauthorized',
                        {'WWW-Authenticate': 'Bearer'},
                    )
                identity = (
                    'key:' + hashlib.sha256(key.encode()).hexdigest()[:16]
                )

            if limiter is not None:
                allowed, wait = await spend(identity)
                if not allowed:
                    return _rejection(
                        429,
                        'Too Many Requests',
                        {'Retry-After': str(int(wait) + 1)},
                    )
        except StoreUnavailable:
            return _rejection(
                503, 'Session store unavailable', {'Retry-After': '1'},
            )
        return None

    class Protect:
        """Pure ASGI middleware: gate each request, then time it.

        Written as plain ASGI rather than @app.middleware('http'), which
        costs a task and a stream per request.
        """

        def __init__(self, inner) -> None:
            self.inner = inner

        async def __call__(self, scope, receive, send) -> None:
            if scope['type'] != 'http':
                await self.inner(scope, receive, send)
                return

            started = time.perf_counter()
            status = [500]

            async def watching_send(message) -> None:
                if message['type'] == 'http.response.start':
                    status[0] = message['status']
                await send(message)

            rejection = await _gate(Request(scope, receive))
            if rejection is not None:
                await rejection(scope, receive, watching_send)
            else:
                await self.inner(scope, receive, watching_send)

            route = scope.get('route')
            label = getattr(route, 'path', None) or 'unmatched'
            stats.observe(label, status[0], time.perf_counter() - started)

    app.add_middleware(Protect)

    @app.get('/health')
    def health() -> dict[str, Any]:
        """Report that the service is up and which protections are on."""
        judge_on = guard.judge is not None and guard.judge.enabled
        return {
            'status': 'ok',
            'version': app.version,
            'llm_judge': judge_on,
            'judge_paused': bool(
                judge_on and getattr(guard.judge, 'breaker_open', False)
            ),
            'auth_required': bool(config.api_keys),
            'rate_limited': limiter is not None,
            'audit_log': guard.audit_store is not None,
            'audit_signed': (
                guard.audit_store is not None and guard.audit_store.signed
            ),
            'session_ttl': guard.session_ttl,
            'session_store': guard.store.kind,
            'metrics': stats.kind,
        }

    @app.get('/ready')
    def ready() -> JSONResponse:
        """Readiness probe: fails while the session store is unreachable."""
        ok = guard.store.ping()
        return JSONResponse(
            status_code=200 if ok else 503,
            content={'ready': ok, 'session_store': guard.store.kind},
        )

    @app.get('/metrics')
    def prometheus() -> PlainTextResponse:
        """Expose metrics in Prometheus text format."""
        extra: dict[str, float] = {}
        count = guard.store.count()
        if count is not None:
            extra['sessions_active'] = count
        judge = guard.judge
        if judge is not None and judge.enabled:
            for key, value in judge.stats().items():
                extra['judge_' + key + '_process_total'] = value
            extra['judge_paused'] = 1 if judge.breaker_open else 0
        return PlainTextResponse(
            stats.render(extra),
            media_type='text/plain; version=0.0.4',
        )

    @app.post('/sessions')
    def open_session(body: SessionRequest) -> dict[str, str]:
        """Open a new session."""
        return {'session_id': guard.new_session(body.user_prompt)}

    @app.post('/sessions/{session_id}/ingest')
    def ingest(session_id: str, body: IngestRequest) -> dict[str, Any]:
        """Label content and return its trust level and injection score."""
        with _session_scope():
            item = guard.ingest(
                session_id,
                body.text,
                source=body.source,
                sensitive=body.sensitive,
            )
        stats.inc('ingest_total', {
            'trust': item.trust.value,
            'flagged': str(item.injection_score >= 0.5).lower(),
        })
        return {
            'item_id': item.item_id,
            'trust': item.trust.value,
            'injection_score': item.injection_score,
            'sensitive': item.sensitive,
            'findings': [
                {
                    'rule_id': finding.rule_id,
                    'description': finding.description,
                    'excerpt': finding.excerpt,
                }
                for finding in item.findings
            ],
        }

    @app.post('/sessions/{session_id}/check-output')
    def check_output(
        session_id: str,
        body: CheckOutputRequest,
    ) -> dict[str, Any]:
        """Check an answer for links or images that leak data."""
        with _session_scope():
            result = guard.check_output(session_id, body.text)
        return {
            'verdict': result.verdict,
            'safe_text': result.safe_text,
            'findings': [f.__dict__ for f in result.findings],
        }

    @app.post('/sessions/{session_id}/model-output')
    def model_output(
        session_id: str,
        body: ModelOutputRequest,
    ) -> dict[str, Any]:
        """Record model-written text and report whether it carries taint."""
        with _session_scope():
            result = guard.record_model_output(session_id, body.text)
        item = result.item
        return {
            'derived': result.derived,
            'item_id': item.item_id if item else None,
            'trust': item.trust.value if item else None,
            'injection_score': item.injection_score if item else 0.0,
            'sensitive': item.sensitive if item else False,
            'derived_from': result.origins,
        }

    @app.post('/sessions/{session_id}/authorize')
    def authorize(
        session_id: str,
        body: AuthorizeRequest,
    ) -> dict[str, Any]:
        """Return allow, confirm or block for a proposed tool call."""
        with _session_scope():
            decision = guard.authorize(session_id, body.tool, body.args)
        stats.inc('decisions_total', {
            'verdict': decision.verdict.value, 'rule': decision.rule_id,
        })
        return {
            'verdict': decision.verdict.value,
            'rule_id': decision.rule_id,
            'reason': decision.reason,
            'evidence': decision.evidence,
        }

    @app.get('/sessions/{session_id}/audit')
    def audit(session_id: str) -> dict[str, Any]:
        """Return the audit trail of a session."""
        with _session_scope():
            events = guard.audit(session_id)
        return {
            'session_id': session_id,
            'events': [
                {
                    'timestamp': event.timestamp,
                    'kind': event.kind,
                    'summary': event.summary,
                    'detail': event.detail,
                }
                for event in events
            ],
        }

    @app.post('/tools')
    def register_tools(body: ToolsRequest) -> dict[str, Any]:
        """Register tool definitions and return the profiles in force.

        Hand-written profiles are never replaced through the API.
        """
        try:
            summaries = guard.policy.config.register_tools(body.tools)
        except ValueError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        return {'tools': summaries}

    @app.get('/tools')
    def list_tools() -> dict[str, Any]:
        """List every tool profile currently in force."""
        config_in_force = guard.policy.config
        return {
            'tools': [
                {
                    'tool': name,
                    'risk': profile.risk.value,
                    'target_args': list(profile.target_args),
                    'has_schema': name in config_in_force.schemas,
                    'generated': name in config_in_force.generated,
                }
                for name, profile in sorted(config_in_force.profiles.items())
            ],
        }

    @app.get('/audit/verify')
    def verify_audit(expected_head: str | None = None) -> dict[str, Any]:
        """Re-check the audit log's hash chain."""
        if guard.audit_store is None:
            return {'enabled': False}
        result = guard.audit_store.verify(expected_head=expected_head)
        return {
            'enabled': True,
            'signed': guard.audit_store.signed,
            'ok': result.ok,
            'records': result.records,
            'head': result.head,
            'error_line': result.error_line,
            'message': result.message,
        }

    @app.get('/audit/export')
    def export_audit(
        session_id: str | None = None,
        limit: int = 1000,
    ) -> dict[str, Any]:
        """Export audit log records, newest limit records at most."""
        if guard.audit_store is None:
            return {'enabled': False, 'records': []}
        limit = max(1, min(limit, MAX_EXPORT_RECORDS))
        records = guard.audit_store.export(session_id)
        return {
            'enabled': True,
            'head': guard.audit_store.head,
            'truncated': len(records) > limit,
            'records': records[-limit:],
        }

    return app


# the default app reads its protections, Redis URL and the Meta judge key
# from the environment (see settings.py)
_settings = ProxySettings.from_env()
_stack = build_stack(_settings)
app = create_app(
    _stack.firewall, _settings, limiter=_stack.limiter, metrics=_stack.metrics,
)
