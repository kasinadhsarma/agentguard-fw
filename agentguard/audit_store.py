"""A persistent, tamper-evident audit log.

Every audit event is appended to a JSON Lines file. Each record carries
the hash of the record before it, so editing, deleting or reordering any
line breaks the chain from that point on, and verify() reports where.

    record["hash"] = H(previous_hash + "|" + canonical_json(record))

H is SHA-256, or HMAC-SHA-256 when a secret key is given. The difference
matters:

  * Without a key, the chain detects accidental damage and partial
    edits. Someone who can rewrite the whole file can also recompute
    every hash, so it proves little against that attacker.
  * With a key kept outside the file's reach, an attacker who can only
    write the file cannot forge a valid chain.

Neither mode detects truncation of the tail by itself. Store the value of
`head` somewhere else (a ticket, another system) and pass it to verify()
as expected_head to catch that.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import AuditEvent


GENESIS_HASH = '0' * 64


@dataclass
class VerifyResult:
    """Outcome of checking a whole audit file."""

    ok: bool
    records: int
    head: str
    error_line: int | None = None
    message: str = ''


def canonical(record: dict[str, Any]) -> str:
    """Serialize a record the same way every time, for hashing."""
    return json.dumps(
        record,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=True,
        default=str,
    )


class AuditStore:
    """Append-only, hash-chained audit file."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        key: bytes | str | None = None,
        fsync: bool = False,
    ) -> None:
        """Open (or create) the file and continue its chain."""
        self.path = Path(path)
        self.key = key.encode() if isinstance(key, str) else key
        self.fsync = fsync
        self._lock = threading.Lock()
        self._seq = 0
        self._head = GENESIS_HASH

        if self.path.exists():
            self._resume()
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.touch(mode=0o600)

    @property
    def head(self) -> str:
        """Hash of the most recent record (the chain's current tip)."""
        return self._head

    @property
    def signed(self) -> bool:
        """True when records are protected with an HMAC key."""
        return self.key is not None

    def _digest(self, previous: str, body: str) -> str:
        """Hash one record body together with the previous hash."""
        message = (previous + '|' + body).encode()
        if self.key is not None:
            return hmac.new(self.key, message, hashlib.sha256).hexdigest()
        return hashlib.sha256(message).hexdigest()

    def _resume(self) -> None:
        """Read the last record so new appends extend the chain."""
        last = None
        with self.path.open('r', encoding='utf-8') as handle:
            for line in handle:
                if line.strip():
                    last = line
        if last is None:
            return
        record = json.loads(last)
        self._seq = int(record['seq'])
        self._head = str(record['hash'])

    def append(self, session_id: str, event: AuditEvent) -> dict[str, Any]:
        """Add one event to the chain and return the stored record."""
        with self._lock:
            record: dict[str, Any] = {
                'seq': self._seq + 1,
                'session_id': session_id,
                'timestamp': event.timestamp,
                'kind': event.kind,
                'summary': event.summary,
                'detail': event.detail,
                'prev': self._head,
            }
            record['hash'] = self._digest(self._head, canonical(record))

            with self.path.open('a', encoding='utf-8') as handle:
                handle.write(canonical(record) + '\n')
                handle.flush()
                if self.fsync:
                    os.fsync(handle.fileno())

            self._seq = record['seq']
            self._head = record['hash']
            return record

    def export(self, session_id: str | None = None) -> list[dict[str, Any]]:
        """Return stored records, optionally only those of one session."""
        records: list[dict[str, Any]] = []
        with self.path.open('r', encoding='utf-8') as handle:
            for line in handle:
                if not line.strip():
                    continue
                record = json.loads(line)
                if session_id is None or record['session_id'] == session_id:
                    records.append(record)
        return records

    def verify(self, expected_head: str | None = None) -> VerifyResult:
        """Recompute the whole chain and report the first break, if any."""
        previous = GENESIS_HASH
        count = 0
        with self.path.open('r', encoding='utf-8') as handle:
            for number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                    stored = record.pop('hash')
                except (ValueError, KeyError):
                    return self._broken(count, previous, number, 'unreadable record')

                if record.get('seq') != count + 1:
                    return self._broken(count, previous, number, 'sequence gap')
                if record.get('prev') != previous:
                    return self._broken(count, previous, number, 'chain link broken')

                expected = self._digest(previous, canonical(record))
                if not hmac.compare_digest(expected, str(stored)):
                    return self._broken(count, previous, number, 'hash mismatch')

                previous = stored
                count += 1

        if expected_head is not None and previous != expected_head:
            return VerifyResult(
                ok=False,
                records=count,
                head=previous,
                message='head differs from the expected value (tail removed?)',
            )
        return VerifyResult(ok=True, records=count, head=previous)

    @staticmethod
    def _broken(
        count: int,
        previous: str,
        line: int,
        message: str,
    ) -> VerifyResult:
        """Build a failed result pointing at the offending line."""
        return VerifyResult(
            ok=False,
            records=count,
            head=previous,
            error_line=line,
            message=message,
        )
