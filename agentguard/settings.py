"""Settings for running the firewall as a service.

Everything comes from environment variables, so the same code runs on a
laptop and behind a gateway:

  AGENTGUARD_API_KEYS    comma-separated keys; when set, every endpoint
                         except /health requires one
  AGENTGUARD_RATE_LIMIT  requests per minute per caller (off if unset)
  AGENTGUARD_RATE_BURST  bucket size (defaults to the per-minute rate)
  AGENTGUARD_SESSION_TTL seconds of inactivity before a session expires
  AGENTGUARD_AUDIT_FILE  path of the hash-chained audit log (off if unset);
                         $VARS are expanded, e.g. audit-$HOSTNAME.jsonl gives
                         every pod its own chain
  AGENTGUARD_AUDIT_KEY   HMAC key for the audit log (recommended)
  AGENTGUARD_AUDIT_FSYNC 1 to fsync every audit record (slower, safer)
  AGENTGUARD_REDIS_URL   share sessions, rate limits and metrics between
                         workers through Redis (redis://host:6379/0)
  AGENTGUARD_REDIS_MAX_CONNECTIONS  pool size per worker (default 50)
  MODEL_API_KEY          enables the Meta Model API judge

With nothing set the service runs open, which is fine on localhost for a
demo and wrong anywhere else. /health reports which protections are on.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from string import Template
from typing import Any, Mapping

from .audit_store import AuditStore
from .firewall import Firewall
from .judge import MetaJudge
from .metrics import Metrics, RedisMetrics
from .ratelimit import RedisRateLimiter, TokenBucketLimiter
from .sessions import RedisSessionStore


@dataclass(frozen=True)
class ProxySettings:
    """Protections for the HTTP proxy."""

    api_keys: frozenset[str] = frozenset()
    rate_limit_per_minute: int | None = None
    rate_limit_burst: int | None = None
    session_ttl: float | None = None
    audit_file: str | None = None
    audit_key: str | None = None
    audit_fsync: bool = False
    redis_url: str | None = None
    redis_max_connections: int = 50

    @classmethod
    def from_env(
        cls,
        environ: Mapping[str, str] | None = None,
    ) -> 'ProxySettings':
        """Read settings from the environment, failing on bad numbers."""
        env = os.environ if environ is None else environ

        keys = frozenset(
            key.strip()
            for key in env.get('AGENTGUARD_API_KEYS', '').split(',')
            if key.strip()
        )
        return cls(
            api_keys=keys,
            rate_limit_per_minute=_optional_int(env, 'AGENTGUARD_RATE_LIMIT'),
            rate_limit_burst=_optional_int(env, 'AGENTGUARD_RATE_BURST'),
            session_ttl=_optional_float(env, 'AGENTGUARD_SESSION_TTL'),
            audit_file=_expand(env, 'AGENTGUARD_AUDIT_FILE'),
            audit_key=env.get('AGENTGUARD_AUDIT_KEY') or None,
            audit_fsync=env.get('AGENTGUARD_AUDIT_FSYNC', '') in ('1', 'true'),
            redis_url=env.get('AGENTGUARD_REDIS_URL') or None,
            redis_max_connections=(
                _optional_int(env, 'AGENTGUARD_REDIS_MAX_CONNECTIONS') or 50
            ),
        )


@dataclass
class Stack:
    """Everything the proxy needs, wired from the settings."""

    firewall: Firewall
    limiter: Any
    metrics: Metrics
    redis: Any = None


def connect_redis(settings: ProxySettings) -> Any:
    """Open a pooled Redis client, or None when no URL is configured."""
    if not settings.redis_url:
        return None
    import redis

    return redis.Redis.from_url(
        settings.redis_url,
        decode_responses=True,
        max_connections=settings.redis_max_connections,
        socket_timeout=2.0,
        socket_connect_timeout=2.0,
        health_check_interval=30,
    )


def build_stack(settings: ProxySettings, client: Any = None) -> Stack:
    """Create the firewall, limiter and metrics for one worker.

    With a Redis URL, sessions, rate-limit buckets and metrics all live in
    Redis and every worker sees the same state. Without one, each is local
    to the process, which is only right for a single worker.
    """
    client = client if client is not None else connect_redis(settings)
    store = audit = None
    if settings.audit_file:
        audit = AuditStore(
            settings.audit_file,
            key=settings.audit_key,
            fsync=settings.audit_fsync,
        )

    if client is not None:
        store = RedisSessionStore(client, ttl=settings.session_ttl)

    limiter = None
    if settings.rate_limit_per_minute:
        if client is not None:
            limiter = RedisRateLimiter(
                client,
                per_minute=settings.rate_limit_per_minute,
                burst=settings.rate_limit_burst,
            )
        else:
            limiter = TokenBucketLimiter(
                per_minute=settings.rate_limit_per_minute,
                burst=settings.rate_limit_burst,
            )

    firewall = Firewall(
        judge=MetaJudge(),
        audit_store=audit,
        session_ttl=settings.session_ttl,
        store=store,
    )
    metrics = RedisMetrics(client) if client is not None else Metrics()
    return Stack(firewall, limiter, metrics, client)


def build_firewall(settings: ProxySettings) -> Firewall:
    """Create a firewall wired to the audit log, TTL and the Meta judge."""
    return build_stack(settings).firewall


def _expand(env: Mapping[str, str], name: str) -> str | None:
    """Read a path and fill in $VARIABLES, so each pod can name its own file."""
    raw = env.get(name, '').strip()
    if not raw:
        return None
    return Template(raw).safe_substitute(env)


def _optional_int(env: Mapping[str, str], name: str) -> int | None:
    """Parse a positive integer variable, or None when unset."""
    raw = env.get(name, '').strip()
    if not raw:
        return None
    value = int(raw)
    if value <= 0:
        raise ValueError(name + ' must be a positive integer')
    return value


def _optional_float(env: Mapping[str, str], name: str) -> float | None:
    """Parse a positive number variable, or None when unset."""
    raw = env.get(name, '').strip()
    if not raw:
        return None
    value = float(raw)
    if value <= 0:
        raise ValueError(name + ' must be positive')
    return value
