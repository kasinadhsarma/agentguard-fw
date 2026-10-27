"""Counters and a latency histogram in Prometheus text format.

With one worker the counters live in memory. With several workers they
are kept in Redis (HINCRBY), so a scrape of any worker reports the whole
fleet. Recording a metric never fails a request: errors are swallowed.

Metrics (all prefixed agentguard_):

  requests_total{route,status}         HTTP requests by route and status
  request_seconds_*{route}             latency histogram per route
  decisions_total{verdict,rule}        authorize outcomes
  ingest_total{trust,flagged}          content labeled, and whether the
                                       detector scored it as suspicious

Routes are the path templates (/sessions/{session_id}/ingest), never raw
paths, so the label set stays small.
"""

from __future__ import annotations

import json
import threading
from typing import Any

PREFIX = 'agentguard_'
BUCKETS = (0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5)
HASH_KEY = 'ag:metrics'

HELP = {
    'requests_total': ('counter', 'HTTP requests by route and status.'),
    'decisions_total': ('counter', 'Tool call decisions by verdict and rule.'),
    'ingest_total': ('counter', 'Content items labeled.'),
    'request_seconds': ('histogram', 'Request latency in seconds.'),
}


def _field(name: str, labels: dict[str, str]) -> str:
    """Encode one series as a stable string key."""
    return json.dumps([name, sorted(labels.items())], separators=(',', ':'))


def _escape(value: str) -> str:
    """Escape a label value for the text format."""
    return (
        value.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
    )


def _series(name: str, labels: dict[str, str], value: float) -> str:
    """Format one sample line."""
    if labels:
        body = ','.join(
            key + '="' + _escape(str(val)) + '"'
            for key, val in sorted(labels.items())
        )
        return PREFIX + name + '{' + body + '} ' + _format(value)
    return PREFIX + name + ' ' + _format(value)


def _format(value: float) -> str:
    """Print integers without a decimal point."""
    return str(int(value)) if float(value).is_integer() else repr(value)


class Metrics:
    """In-memory counters; RedisMetrics shares them across workers."""

    kind = 'memory'

    def __init__(self) -> None:
        """Start with no samples."""
        self._lock = threading.Lock()
        self._counts: dict[str, int] = {}

    # storage hooks ---------------------------------------------------

    def _add(self, increments: dict[str, int]) -> None:
        """Add to several counters at once."""
        with self._lock:
            for key, amount in increments.items():
                self._counts[key] = self._counts.get(key, 0) + amount

    def _all(self) -> dict[str, int]:
        """Return every counter."""
        with self._lock:
            return dict(self._counts)

    # recording -------------------------------------------------------

    def inc(self, name: str, labels: dict[str, str], amount: int = 1) -> None:
        """Count one event."""
        try:
            self._add({_field(name, labels): amount})
        except Exception:  # metrics must never break a request
            pass

    def observe(self, route: str, status: int, seconds: float) -> None:
        """Record one finished request: count it and time it."""
        bucket = next((b for b in BUCKETS if seconds <= b), None)
        le = 'inf' if bucket is None else repr(bucket)
        increments = {
            _field('requests_total', {
                'route': route, 'status': str(status),
            }): 1,
            _field('request_seconds_bucket', {'route': route, 'le': le}): 1,
            _field('request_seconds_sum_us', {'route': route}): int(
                seconds * 1_000_000,
            ),
            _field('request_seconds_count', {'route': route}): 1,
        }
        try:
            self._add(increments)
        except Exception:
            pass

    # exposition ------------------------------------------------------

    def render(self, extra: dict[str, float] | None = None) -> str:
        """Return all samples in Prometheus text format."""
        samples = self._all()
        lines: list[str] = []
        done_headers: set[str] = set()

        def header(name: str) -> None:
            if name in done_headers or name not in HELP:
                return
            done_headers.add(name)
            kind, text = HELP[name]
            lines.append('# HELP ' + PREFIX + name + ' ' + text)
            lines.append('# TYPE ' + PREFIX + name + ' ' + kind)

        buckets: dict[str, dict[str, int]] = {}
        sums: dict[str, int] = {}
        counts: dict[str, int] = {}
        plain: list[tuple[str, dict[str, str], int]] = []

        for key, value in samples.items():
            name, pairs = json.loads(key)
            labels = dict(pairs)
            if name == 'request_seconds_bucket':
                buckets.setdefault(labels['route'], {})[labels['le']] = value
            elif name == 'request_seconds_sum_us':
                sums[labels['route']] = value
            elif name == 'request_seconds_count':
                counts[labels['route']] = value
            else:
                plain.append((name, labels, value))

        for name, labels, value in sorted(
            plain, key=lambda row: (row[0], sorted(row[1].items())),
        ):
            header(name)
            lines.append(_series(name, labels, value))

        if counts:
            header('request_seconds')
            for route in sorted(counts):
                running = 0
                per = buckets.get(route, {})
                for bound in BUCKETS:
                    running += per.get(repr(bound), 0)
                    lines.append(_series(
                        'request_seconds_bucket',
                        {'route': route, 'le': repr(bound)}, running,
                    ))
                lines.append(_series(
                    'request_seconds_bucket',
                    {'route': route, 'le': '+Inf'}, counts[route],
                ))
                lines.append(_series(
                    'request_seconds_sum', {'route': route},
                    sums.get(route, 0) / 1_000_000,
                ))
                lines.append(_series(
                    'request_seconds_count', {'route': route}, counts[route],
                ))

        for name, value in sorted((extra or {}).items()):
            lines.append('# TYPE ' + PREFIX + name + ' gauge')
            lines.append(_series(name, {}, value))
        return '\n'.join(lines) + '\n'


class RedisMetrics(Metrics):
    """Counters kept in one Redis hash, shared by every worker.

    Recording is buffered in memory and flushed to Redis once a second by
    a background thread, so a request costs no network round trip for its
    metrics. A scrape flushes first, so it sees everything this worker
    counted. A worker that dies loses at most about one second of counts.
    """

    kind = 'redis'
    FLUSH_SECONDS = 1.0
    MAX_BUFFERED = 10_000

    def __init__(self, client: Any, flush_seconds: float | None = None):
        """Wrap a redis.Redis client (decode_responses=True)."""
        super().__init__()
        self.client = client
        self.flush_seconds = flush_seconds or self.FLUSH_SECONDS
        self._thread: threading.Thread | None = None

    def _add(self, increments: dict[str, int]) -> None:
        """Buffer increments; the flusher sends them later."""
        with self._lock:
            for key, amount in increments.items():
                self._counts[key] = self._counts.get(key, 0) + amount
            if self._thread is None:
                self._thread = threading.Thread(
                    target=self._loop, name='metrics-flush', daemon=True,
                )
                self._thread.start()

    def _loop(self) -> None:
        """Flush forever; a Redis outage just delays the flush."""
        import time

        while True:
            time.sleep(self.flush_seconds)
            try:
                self.flush()
            except Exception:
                pass

    def flush(self) -> None:
        """Send buffered increments to Redis."""
        with self._lock:
            pending, self._counts = self._counts, {}
        if not pending:
            return
        try:
            pipe = self.client.pipeline(transaction=False)
            for key, amount in pending.items():
                pipe.hincrby(HASH_KEY, key, amount)
            pipe.execute()
        except Exception:
            # keep the counts for the next try, within a bound
            with self._lock:
                if len(self._counts) < self.MAX_BUFFERED:
                    for key, amount in pending.items():
                        self._counts[key] = self._counts.get(key, 0) + amount
            raise

    def _all(self) -> dict[str, int]:
        """Flush this worker's buffer, then read the fleet-wide counters."""
        try:
            self.flush()
        except Exception:
            pass
        return {k: int(v) for k, v in self.client.hgetall(HASH_KEY).items()}
