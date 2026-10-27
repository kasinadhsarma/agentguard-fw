"""Settings for running the firewall as a service.

Everything comes from environment variables, so the same code runs on a
laptop and behind a gateway:

  AGENTGUARD_API_KEYS    comma-separated keys; when set, every endpoint
                         except /health requires one
  AGENTGUARD_RATE_LIMIT  requests per minute per caller (off if unset)
  AGENTGUARD_RATE_BURST  bucket size (defaults to the per-minute rate)
  AGENTGUARD_SESSION_TTL seconds of inactivity before a session expires
  AGENTGUARD_AUDIT_FILE  path of the hash-chained audit log (off if unset)
  AGENTGUARD_AUDIT_KEY   HMAC key for the audit log (recommended)
  MODEL_API_KEY          enables the Meta Model API judge

With nothing set the service runs open, which is fine on localhost for a
demo and wrong anywhere else. /health reports which protections are on.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping

from .audit_store import AuditStore
from .firewall import Firewall
from .judge import MetaJudge


@dataclass(frozen=True)
class ProxySettings:
    """Protections for the HTTP proxy."""

    api_keys: frozenset[str] = frozenset()
    rate_limit_per_minute: int | None = None
    rate_limit_burst: int | None = None
    session_ttl: float | None = None
    audit_file: str | None = None
    audit_key: str | None = None

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
            audit_file=env.get('AGENTGUARD_AUDIT_FILE') or None,
            audit_key=env.get('AGENTGUARD_AUDIT_KEY') or None,
        )


def build_firewall(settings: ProxySettings) -> Firewall:
    """Create a firewall wired to the audit log, TTL and the Meta judge."""
    store = None
    if settings.audit_file:
        store = AuditStore(settings.audit_file, key=settings.audit_key)
    return Firewall(
        judge=MetaJudge(),
        audit_store=store,
        session_ttl=settings.session_ttl,
    )


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
