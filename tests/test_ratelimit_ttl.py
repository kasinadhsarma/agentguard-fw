"""Tests for the rate limiter and session expiry."""

import pytest

from agentguard import Firewall
from agentguard.ratelimit import TokenBucketLimiter


class FakeClock:
    """A clock the test can move by hand."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def test_limiter_allows_a_burst_then_refuses() -> None:
    """Callers can burst up to the bucket size and no further."""
    clock = FakeClock()
    limiter = TokenBucketLimiter(per_minute=60, burst=3, clock=clock)

    assert [limiter.check('a')[0] for _ in range(4)] == [
        True, True, True, False,
    ]


def test_limiter_refills_over_time_and_reports_wait() -> None:
    """Tokens come back at the configured rate."""
    clock = FakeClock()
    limiter = TokenBucketLimiter(per_minute=60, burst=1, clock=clock)

    assert limiter.check('a') == (True, 0.0)
    allowed, wait = limiter.check('a')
    assert allowed is False and 0 < wait <= 1.0

    clock.now += 1.0
    assert limiter.check('a')[0] is True


def test_callers_have_separate_buckets() -> None:
    """One noisy caller does not starve another."""
    limiter = TokenBucketLimiter(per_minute=60, burst=1, clock=FakeClock())
    assert limiter.check('a')[0] is True
    assert limiter.check('a')[0] is False
    assert limiter.check('b')[0] is True


def test_limiter_rejects_a_non_positive_rate() -> None:
    """A zero or negative rate is a configuration error."""
    with pytest.raises(ValueError):
        TokenBucketLimiter(per_minute=0)


def test_idle_sessions_expire() -> None:
    """A session unused for longer than the TTL disappears."""
    clock = FakeClock()
    firewall = Firewall(session_ttl=60, clock=clock)
    session = firewall.new_session('hello')

    clock.now += 30
    firewall.get(session)           # activity renews the session
    clock.now += 50
    firewall.get(session)           # still alive: 50s since last use

    clock.now += 61
    with pytest.raises(KeyError):
        firewall.get(session)
    assert session not in firewall.sessions


def test_purge_removes_only_expired_sessions() -> None:
    """purge_expired() reports how many sessions it dropped."""
    clock = FakeClock()
    firewall = Firewall(session_ttl=60, clock=clock)
    old = firewall.new_session('old')
    clock.now += 50
    fresh = firewall.new_session('fresh')
    clock.now += 50                 # old is 100s idle, fresh only 50s

    assert firewall.purge_expired() == 1
    assert old not in firewall.sessions and fresh in firewall.sessions


def test_no_ttl_means_sessions_never_expire() -> None:
    """The default keeps sessions until the process ends."""
    clock = FakeClock()
    firewall = Firewall(clock=clock)
    session = firewall.new_session('hello')
    clock.now += 10 ** 9
    assert firewall.get(session).session_id == session
