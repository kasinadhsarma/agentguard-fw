"""Shared data models for the AgentGuard prompt injection firewall."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Trust(str, Enum):
    """Trust label attached to every piece of content an agent sees."""

    TRUSTED = 'trusted'
    UNTRUSTED = 'untrusted'


class Verdict(str, Enum):
    """Outcome of authorizing a single tool call."""

    ALLOW = 'allow'
    CONFIRM = 'confirm'
    BLOCK = 'block'


class ToolRisk(str, Enum):
    """How dangerous a tool is if an attacker controls its arguments."""

    READ = 'read'
    SENSITIVE_READ = 'sensitive_read'
    SIDE_EFFECT = 'side_effect'


# sources that carry the user's own authority; everything else is untrusted
TRUSTED_SOURCES = frozenset({'user', 'system'})


@dataclass
class Finding:
    """One injection pattern that matched inside a piece of content."""

    rule_id: str
    description: str
    weight: float
    excerpt: str


@dataclass
class ContentItem:
    """A piece of content that entered the agent's context."""

    item_id: int
    text: str
    source: str
    trust: Trust
    injection_score: float = 0.0
    findings: list[Finding] = field(default_factory=list)
    sensitive: bool = False
    # ids of the untrusted items this content was derived from (model output)
    derived_from: list[int] = field(default_factory=list)


@dataclass
class Decision:
    """The firewall's ruling on one tool call, with the reason why."""

    verdict: Verdict
    rule_id: str
    reason: str
    tool: str
    args: dict[str, Any]
    evidence: list[str] = field(default_factory=list)


@dataclass
class AuditEvent:
    """One entry in a session's audit trail."""

    timestamp: float
    kind: str
    summary: str
    detail: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def create(
        kind: str,
        summary: str,
        detail: dict[str, Any] | None = None,
    ) -> 'AuditEvent':
        """Build an audit event stamped with the current time."""
        return AuditEvent(
            timestamp=time.time(),
            kind=kind,
            summary=summary,
            detail=detail or {},
        )
