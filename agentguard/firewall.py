"""The firewall: ties detector, judge, taint tracker and policy together."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable

from . import detector
from .audit_store import AuditStore
from .judge import MetaJudge
from .models import (
    TRUSTED_SOURCES,
    AuditEvent,
    ContentItem,
    Decision,
    Finding,
    Trust,
)
from .policy import PolicyConfig, PolicyEngine
from .sessions import (
    MemorySessionStore,
    Session,
    SessionStore,
)


# tool results from these sources hold secrets the agent must not leak
SENSITIVE_SOURCE_PREFIXES = ('tool:read_file',)


@dataclass
class ModelOutputResult:
    """What recording a piece of model output found out."""

    derived: bool
    item: ContentItem | None = None
    origins: list[int] = field(default_factory=list)


class Firewall:
    """Sits between an agent and its tools."""

    def __init__(
        self,
        config: PolicyConfig | None = None,
        judge: MetaJudge | None = None,
        audit_store: AuditStore | None = None,
        session_ttl: float | None = None,
        clock: Callable[[], float] = time.time,
        store: SessionStore | None = None,
    ) -> None:
        """Create a firewall.

        judge:        a MetaJudge enables the LLM layer
        audit_store:  also writes every event to a hash-chained file
        session_ttl:  seconds of inactivity before a session expires
                      (ignored when a store is given; the store owns it)
        clock:        time source for the in-memory store, for tests
        store:        where sessions live; defaults to this process's memory,
                      pass a RedisSessionStore to share them across workers
        """
        self.policy = PolicyEngine(config)
        self.judge = judge
        self.audit_store = audit_store
        self.clock = clock
        self.store: SessionStore = store or MemorySessionStore(
            ttl=session_ttl, clock=clock,
        )

    @property
    def session_ttl(self) -> float | None:
        """Seconds of inactivity before a session expires."""
        return self.store.ttl

    @property
    def sessions(self) -> dict[str, Session]:
        """The session dict of an in-memory store (tests and demos)."""
        return self.store.sessions  # type: ignore[attr-defined]

    def new_session(self, user_prompt: str = '') -> str:
        """Open a session, optionally seeded with the user's request."""
        self.store.purge_expired()
        session_id = uuid.uuid4().hex[:12]
        self.store.create(session_id)
        if user_prompt:
            self.ingest(session_id, user_prompt, source='user')
        return session_id

    def get(self, session_id: str) -> Session:
        """Return a live session with its content, or raise KeyError.

        Every successful lookup counts as activity and renews the session.
        """
        return self.store.load(session_id)

    def touch(self, session_id: str) -> None:
        """Check a session exists and renew it, without loading content."""
        self.store.touch(session_id)

    def purge_expired(self) -> int:
        """Drop every expired session and return how many were removed."""
        return self.store.purge_expired()

    def _event(
        self,
        session_id: str,
        kind: str,
        summary: str,
        detail: dict[str, Any],
    ) -> AuditEvent:
        """Build an audit event and write it to the audit log, if any."""
        event = AuditEvent.create(kind=kind, summary=summary, detail=detail)
        if self.audit_store is not None:
            self.audit_store.append(session_id, event)
        return event

    def ingest(
        self,
        session_id: str,
        text: str,
        source: str,
        sensitive: bool | None = None,
    ) -> ContentItem:
        """Label content and scan it before it reaches the agent."""
        # reserving the id first also proves the session exists, before
        # any money is spent on the judge
        item_id = self.store.reserve_item_id(session_id)
        trust = (
            Trust.TRUSTED if source in TRUSTED_SOURCES else Trust.UNTRUSTED
        )
        item = ContentItem(
            item_id=item_id,
            text=text,
            source=source,
            trust=trust,
        )

        if sensitive is None:
            sensitive = source.startswith(SENSITIVE_SOURCE_PREFIXES)
        item.sensitive = bool(sensitive)

        # the slow part (the judge makes a network call) runs before the
        # item is stored, so a session is never held up while it waits
        if trust == Trust.UNTRUSTED:
            self._scan(item)

        event = self._event(
            session_id,
            kind='ingest',
            summary=(
                trust.value + ' content from ' + source +
                ' (injection score ' +
                format(item.injection_score, '.2f') + ')'
            ),
            detail={
                'item_id': item.item_id,
                'source': source,
                'trust': trust.value,
                'score': item.injection_score,
                'sensitive': item.sensitive,
                'findings': [f.rule_id for f in item.findings],
            },
        )
        self.store.record_item(session_id, item, event)
        return item

    def authorize(
        self,
        session_id: str,
        tool: str,
        arguments: dict[str, Any],
    ) -> Decision:
        """Decide whether the agent may run a tool call."""
        session = self.get(session_id)
        decision = self.policy.evaluate(tool, arguments, session.tracker)
        event = self._event(
            session_id,
            kind='decision',
            summary=(
                decision.verdict.value.upper() + ' ' + tool + ' [' +
                decision.rule_id + ']: ' + decision.reason
            ),
            detail={
                'tool': tool,
                'args': arguments,
                'verdict': decision.verdict.value,
                'rule': decision.rule_id,
                'evidence': decision.evidence,
            },
        )
        self.store.append_event(session_id, event)
        return decision

    def record_model_output(
        self,
        session_id: str,
        text: str,
    ) -> ModelOutputResult:
        """Record text the model wrote and keep the taint it carries.

        A summary, rewrite or quote of untrusted content is untrusted
        too. If the text copies a span from an untrusted item, or names
        an address or host that only untrusted content named, it is
        stored as a derived untrusted item. It inherits the highest
        injection score of its origins and is marked sensitive when any
        origin was. Text that draws on no untrusted content is only
        logged: it authorizes nothing, so a target the model invents on
        its own still ends in a confirmation (R3).
        """
        session = self.get(session_id)
        origins = session.tracker.origins_of(text)

        if not origins:
            event = self._event(
                session_id,
                kind='model_output',
                summary='model output with no untrusted origin',
                detail={'derived': False, 'chars': len(text)},
            )
            self.store.append_event(session_id, event)
            return ModelOutputResult(derived=False)

        sources = sorted({origin.source for origin in origins})
        item = ContentItem(
            item_id=self.store.reserve_item_id(session_id),
            text=text,
            source='model:derived(' + ', '.join(sources) + ')',
            trust=Trust.UNTRUSTED,
            derived_from=[origin.item_id for origin in origins],
            sensitive=any(origin.sensitive for origin in origins),
        )
        score, findings = detector.scan(text)
        item.findings = findings
        item.injection_score = max(
            [score] + [origin.injection_score for origin in origins],
        )
        event = self._event(
            session_id,
            kind='model_output',
            summary=(
                'model output derived from ' + ', '.join(sources) +
                ' (inherited score ' +
                format(item.injection_score, '.2f') + ')'
            ),
            detail={
                'derived': True,
                'item_id': item.item_id,
                'derived_from': item.derived_from,
                'score': item.injection_score,
                'sensitive': item.sensitive,
            },
        )
        self.store.record_item(session_id, item, event)
        return ModelOutputResult(
            derived=True,
            item=item,
            origins=item.derived_from,
        )

    def audit(self, session_id: str) -> list[AuditEvent]:
        """Return the full audit trail of a session."""
        return self.store.events(session_id)

    def _scan(self, item: ContentItem) -> None:
        """Run the heuristic detector and, if enabled, the LLM judge.

        Sensitive content (for example the contents of a file the agent
        read) is never sent to the external judge. It is scanned locally
        only, so secrets cannot leave the machine through this layer.
        """
        score, findings = detector.scan(item.text)
        item.injection_score = score
        item.findings = findings

        if self.judge is None or not self.judge.enabled:
            return

        if item.sensitive:
            return

        verdict = self.judge.judge(item.text)
        if not verdict.available or not verdict.injection:
            return

        item.findings.append(
            Finding(
                rule_id='llm_judge',
                description='model judged this content an injection',
                weight=verdict.confidence,
                excerpt=verdict.reason,
            )
        )
        item.injection_score = max(
            item.injection_score,
            detector.SUSPICIOUS_THRESHOLD,
            verdict.confidence,
        )
