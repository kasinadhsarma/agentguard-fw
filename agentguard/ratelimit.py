"""A small in-memory token-bucket rate limiter.

Each caller identity (an API key, or a client address when there is no
valid key) owns a bucket that holds up to `burst` tokens and refills at
`per_minute / 60` tokens per second. A request costs one token.

The limiter lives in the memory of one process. Behind several workers
or machines each one counts separately, so put a shared limiter in front
(a gateway or a Redis-backed limiter) if you need a global limit.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Callable


# how many distinct callers are tracked before the oldest are forgotten
MAX_TRACKED_IDENTITIES = 10_000


class TokenBucketLimiter:
    """Allows a steady request rate per caller, with a short burst."""

    def __init__(
        self,
        per_minute: int,
        burst: int | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Create a limiter; burst defaults to one minute of requests."""
        if per_minute <= 0:
            raise ValueError('per_minute must be positive')
        self.rate = per_minute / 60.0
        self.burst = float(burst if burst is not None else per_minute)
        self.clock = clock
        self._lock = threading.Lock()
        # identity -> (tokens left, time of last update)
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()

    def check(self, identity: str) -> tuple[bool, float]:
        """Spend one token for the caller.

        Returns (allowed, retry_after_seconds). retry_after is 0 when the
        request is allowed.
        """
        now = self.clock()
        with self._lock:
            tokens, stamp = self._buckets.get(identity, (self.burst, now))
            tokens = min(self.burst, tokens + (now - stamp) * self.rate)

            if tokens >= 1.0:
                self._store(identity, tokens - 1.0, now)
                return True, 0.0

            self._store(identity, tokens, now)
            return False, (1.0 - tokens) / self.rate

    def _store(self, identity: str, tokens: float, now: float) -> None:
        """Save a bucket and forget the oldest callers beyond the cap."""
        self._buckets[identity] = (tokens, now)
        self._buckets.move_to_end(identity)
        while len(self._buckets) > MAX_TRACKED_IDENTITIES:
            self._buckets.popitem(last=False)
