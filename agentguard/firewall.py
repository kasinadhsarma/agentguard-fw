"""The firewall: ties detector, judge, taint tracker and policy together."""

from __future__ import annotations

import itertools
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
from .taint import TaintTracker


# tool results from these sources hold secrets the agent must not leak
SENSITIVE_SOURCE_PREFIXES = ('tool:read_file',)


@dataclass
class Session:
    """State for one agent run."""

    session_id: str
    tracker: TaintTracker = field(default_factory=TaintTracker)
    events: list[AuditEvent] = field(default_factory=list)
    decisions: list[Decision] = field(default_factory=list)
    counter: Any = field(default_factory=lambda: itertools.count(1))
    last_used: float = 0.0


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
    ) -> None:
        """Create a firewall.

        judge:        a MetaJudge enables the LLM layer
        audit_store:  also writes every event to a hash-chained file
        session_ttl:  seconds of inactivity before a session expires
        clock:        time source, replaceable in tests
        """
        self.policy = PolicyEngine(config)
        self.judge = judge
        self.audit_store = audit_store
        self.session_ttl = session_ttl
        self.clock = clock
        self.sessions: dict[str, Session] = {}

    def new_session(self, user_prompt: str = '') -> str:
        """Open a session, optionally seeded with the user's request."""
        self.purge_expired()
        session_id = uuid.uuid4().hex[:12]
        session = Session(session_id=session_id, last_used=self.clock())
        self.sessions[session_id] = session
        if user_prompt:
            self.ingest(session_id, user_prompt, source='user')
        return session_id

    def get(self, session_id: str) -> Session:
        """Return a live session, or raise KeyError if missing or expired.

        Every successful lookup counts as activity and renews the session.
        """
        session = self.sessions[session_id]
        now = self.clock()
        if self._is_expired(session, now):
            del self.sessions[session_id]
            raise KeyError(session_id)
        session.last_used = now
        return session

    def purge_expired(self) -> int:
        """Drop every expired session and return how many were removed."""
        now = self.clock()
        stale = [
            session_id
            for session_id, session in self.sessions.items()
            if self._is_expired(session, now)
        ]
        for session_id in stale:
            del self.sessions[session_id]
        return len(stale)

    def _is_expired(self, session: Session, now: float) -> bool:
        """True when the session has been idle longer than the TTL."""
        if self.session_ttl is None:
            return False
        return now - session.last_used > self.session_ttl

    def _log(
        self,
        session: Session,
        kind: str,
        summary: str,
        detail: dict[str, Any],
    ) -> None:
        """Append an audit event to the session and to the store."""
        event = AuditEvent.create(kind=kind, summary=summary, detail=detail)
        session.events.append(event)
        if self.audit_store is not None:
            self.audit_store.append(session.session_id, event)

    def ingest(
        self,
        session_id: str,
        text: str,
        source: str,
        sensitive: bool | None = None,
    ) -> ContentItem:
        """Label content and scan it before it reaches the agent."""
        session = self.get(session_id)
        trust = (
            Trust.TRUSTED if source in TRUSTED_SOURCES else Trust.UNTRUSTED
        )
        item = ContentItem(
            item_id=next(session.counter),
            text=text,
            source=source,
            trust=trust,
        )

        if sensitive is None:
            sensitive = source.startswith(SENSITIVE_SOURCE_PREFIXES)
        item.sensitive = bool(sensitive)

        if trust == Trust.UNTRUSTED:
            self._scan(item)

        session.tracker.add(item)
        self._log(
            session,
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
        session.decisions.append(decision)
        self._log(
            session,
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
            self._log(
                session,
                kind='model_output',
                summary='model output with no untrusted origin',
                detail={'derived': False, 'chars': len(text)},
            )
            return ModelOutputResult(derived=False)

        sources = sorted({origin.source for origin in origins})
        item = ContentItem(
            item_id=next(session.counter),
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
        session.tracker.add(item)
        self._log(
            session,
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
        return ModelOutputResult(
            derived=True,
            item=item,
            origins=item.derived_from,
        )

    def audit(self, session_id: str) -> list[AuditEvent]:
        """Return the full audit trail of a session."""
        return list(self.get(session_id).events)

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
