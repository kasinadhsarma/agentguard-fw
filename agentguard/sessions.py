"""Where session state lives: in this process, or in Redis.

One process can keep sessions in a dict. Many workers behind a load
balancer cannot, because the next request of a session may land on a
different worker. A SessionStore hides that choice from the firewall.

Two implementations share one interface:

  MemorySessionStore   a dict in this process (default, fine for one worker)
  RedisSessionStore    shared by all workers; sessions expire by Redis TTL

The Redis layout is append-only, so concurrent requests never overwrite
each other and no lock is needed:

  ag:{id}:meta        hash   next_id, created
  ag:{id}:items       list   one JSON document per ContentItem
  ag:{id}:events      list   audit events, capped at MAX_EVENTS

{id} is a hash tag, so all keys of a session share one cluster slot.

Round trips per call: authorize 2, ingest 2, model-output 2 to 3. The
decisions themselves are kept as audit events, not as a second list.

Failing closed: when Redis cannot be reached the store raises
StoreUnavailable and the proxy answers 503. It never guesses a verdict.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from .models import (
    AuditEvent,
    ContentItem,
    Finding,
    Trust,
)
from .taint import TaintTracker


# bounds that keep one session from using unlimited memory
MAX_ITEMS = 1000
MAX_EVENTS = 5000


class StoreUnavailable(RuntimeError):
    """The shared session store cannot be reached."""


class SessionFull(RuntimeError):
    """A session reached its item limit."""


@dataclass
class Session:
    """State for one agent run."""

    session_id: str
    tracker: TaintTracker = field(default_factory=TaintTracker)
    events: list[AuditEvent] = field(default_factory=list)
    next_id: int = 0
    last_used: float = 0.0


class SessionStore(Protocol):
    """What the firewall needs from a session store."""

    kind: str
    ttl: float | None

    def create(self, session_id: str) -> None: ...
    def touch(self, session_id: str) -> None: ...
    def load(self, session_id: str) -> Session: ...
    def reserve_item_id(self, session_id: str) -> int: ...
    def record_item(
        self, session_id: str, item: ContentItem, event: AuditEvent,
    ) -> None: ...
    def append_event(self, session_id: str, event: AuditEvent) -> None: ...
    def events(self, session_id: str) -> list[AuditEvent]: ...
    def purge_expired(self) -> int: ...
    def count(self) -> int | None: ...
    def ping(self) -> bool: ...


# ---------------------------------------------------------------- memory


class MemorySessionStore:
    """Sessions in a dict inside this process."""

    kind = 'memory'

    def __init__(
        self,
        ttl: float | None = None,
        clock: Callable[[], float] = time.time,
        max_items: int = MAX_ITEMS,
    ) -> None:
        """Create an empty store; ttl is seconds of idleness allowed."""
        self.ttl = ttl
        self.clock = clock
        self.max_items = max_items
        self.sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    def _expired(self, session: Session, now: float) -> bool:
        """True when the session has been idle longer than the TTL."""
        return self.ttl is not None and now - session.last_used > self.ttl

    def create(self, session_id: str) -> None:
        """Open an empty session."""
        with self._lock:
            self.sessions[session_id] = Session(
                session_id=session_id, last_used=self.clock(),
            )

    def load(self, session_id: str) -> Session:
        """Return a live session and renew it; KeyError if missing or old."""
        with self._lock:
            session = self.sessions[session_id]
            now = self.clock()
            if self._expired(session, now):
                del self.sessions[session_id]
                raise KeyError(session_id)
            session.last_used = now
            return session

    def touch(self, session_id: str) -> None:
        """Renew a session without returning it."""
        self.load(session_id)

    def reserve_item_id(self, session_id: str) -> int:
        """Check the session is live and reserve its next item id."""
        with self._lock:
            session = self.sessions[session_id]
            now = self.clock()
            if self._expired(session, now):
                del self.sessions[session_id]
                raise KeyError(session_id)
            session.last_used = now
            if session.next_id >= self.max_items:
                raise SessionFull(session_id)
            session.next_id += 1
            return session.next_id

    def record_item(
        self,
        session_id: str,
        item: ContentItem,
        event: AuditEvent,
    ) -> None:
        """Add a labeled item and its audit event."""
        self.sessions[session_id].tracker.add(item)
        self.append_event(session_id, event)

    def append_event(self, session_id: str, event: AuditEvent) -> None:
        """Add an audit event, dropping the oldest beyond the cap."""
        events = self.sessions[session_id].events
        events.append(event)
        if len(events) > MAX_EVENTS:
            del events[: len(events) - MAX_EVENTS]

    def events(self, session_id: str) -> list[AuditEvent]:
        """Return the session's audit events."""
        return list(self.load(session_id).events)

    def purge_expired(self) -> int:
        """Drop every expired session and return how many were removed."""
        now = self.clock()
        with self._lock:
            stale = [
                key for key, value in self.sessions.items()
                if self._expired(value, now)
            ]
            for key in stale:
                del self.sessions[key]
        return len(stale)

    def count(self) -> int:
        """Number of sessions held."""
        return len(self.sessions)

    def ping(self) -> bool:
        """A memory store is always reachable."""
        return True


# ------------------------------------------------------------ serialization


def _dumps(value: Any) -> str:
    """Compact JSON; values JSON cannot hold become strings."""
    return json.dumps(value, separators=(',', ':'), default=str)


def item_to_json(item: ContentItem) -> str:
    """Serialize a content item."""
    return _dumps({
        'id': item.item_id,
        'text': item.text,
        'source': item.source,
        'trust': item.trust.value,
        'score': item.injection_score,
        'findings': [
            [f.rule_id, f.description, f.weight, f.excerpt]
            for f in item.findings
        ],
        'sensitive': item.sensitive,
        'derived': item.derived_from,
    })


def item_from_json(raw: str) -> ContentItem:
    """Read a content item back."""
    data = json.loads(raw)
    return ContentItem(
        item_id=data['id'],
        text=data['text'],
        source=data['source'],
        trust=Trust(data['trust']),
        injection_score=data['score'],
        findings=[Finding(*entry) for entry in data['findings']],
        sensitive=data['sensitive'],
        derived_from=data['derived'],
    )


def event_to_json(event: AuditEvent) -> str:
    """Serialize an audit event."""
    return _dumps([event.timestamp, event.kind, event.summary, event.detail])


def event_from_json(raw: str) -> AuditEvent:
    """Read an audit event back."""
    stamp, kind, summary, detail = json.loads(raw)
    return AuditEvent(
        timestamp=stamp, kind=kind, summary=summary, detail=detail,
    )


# ------------------------------------------------------------------ redis


# Check the session exists, renew every key, and take the next item id,
# all in one atomic step. Returns -1 when the session is gone.
_RESERVE_SCRIPT = """
if redis.call('EXISTS', KEYS[1]) == 0 then
  return -1
end
local ttl = tonumber(ARGV[1])
if ttl > 0 then
  for i = 1, #KEYS do
    redis.call('EXPIRE', KEYS[i], ttl)
  end
end
return redis.call('HINCRBY', KEYS[1], 'next_id', 1)
"""


class RedisSessionStore:
    """Sessions in Redis, shared by every worker."""

    kind = 'redis'

    def __init__(
        self,
        client: Any,
        ttl: float | None = None,
        max_items: int = MAX_ITEMS,
        prefix: str = 'ag',
    ) -> None:
        """Wrap a redis.Redis client (decode_responses=True)."""
        self.client = client
        self.ttl = ttl
        self.max_items = max_items
        self.prefix = prefix
        self._reserve = None

    @classmethod
    def from_url(
        cls,
        url: str,
        ttl: float | None = None,
        max_connections: int = 50,
    ) -> 'RedisSessionStore':
        """Connect with a pool and short timeouts so failures surface fast."""
        import redis

        client = redis.Redis.from_url(
            url,
            decode_responses=True,
            max_connections=max_connections,
            socket_timeout=2.0,
            socket_connect_timeout=2.0,
            health_check_interval=30,
        )
        return cls(client, ttl=ttl)

    def _key(self, session_id: str, part: str) -> str:
        """Build a key; {id} is a cluster hash tag."""
        return self.prefix + ':{' + session_id + '}:' + part

    def _call(self, action: Callable[[], Any]) -> Any:
        """Run a Redis action, turning connection errors into 503s."""
        import redis

        try:
            return action()
        except redis.RedisError as error:
            raise StoreUnavailable(type(error).__name__) from error

    def _ttl_seconds(self) -> int | None:
        """The TTL rounded up to whole seconds for EXPIRE."""
        if self.ttl is None:
            return None
        return max(1, int(self.ttl + 0.999))

    PARTS = ('meta', 'items', 'events')

    def create(self, session_id: str) -> None:
        """Open an empty session."""
        def run() -> None:
            pipe = self.client.pipeline(transaction=False)
            pipe.hset(self._key(session_id, 'meta'), mapping={
                'next_id': 0, 'created': time.time(),
            })
            self._expire_all(pipe, session_id)
            pipe.execute()
        self._call(run)

    def _expire_all(self, pipe: Any, session_id: str) -> None:
        """Queue a TTL renewal on every key of the session.

        All keys must be renewed together: if the item list outlived or
        died before the metadata, a session could silently lose the taint
        it had recorded.
        """
        seconds = self._ttl_seconds()
        if seconds is None:
            return
        for part in self.PARTS:
            pipe.expire(self._key(session_id, part), seconds)

    def touch(self, session_id: str) -> None:
        """Renew a session; KeyError if it does not exist."""
        def run() -> bool:
            pipe = self.client.pipeline(transaction=False)
            pipe.exists(self._key(session_id, 'meta'))
            self._expire_all(pipe, session_id)
            return bool(pipe.execute()[0])
        if not self._call(run):
            raise KeyError(session_id)

    def load(self, session_id: str) -> Session:
        """Read the session's items in one round trip (events are separate)."""
        def run() -> list[Any]:
            pipe = self.client.pipeline(transaction=False)
            pipe.exists(self._key(session_id, 'meta'))
            pipe.lrange(self._key(session_id, 'items'), 0, -1)
            self._expire_all(pipe, session_id)
            return pipe.execute()
        found, items = self._call(run)[:2]
        if not found:
            raise KeyError(session_id)

        tracker = TaintTracker()
        for raw in items:
            tracker.add(item_from_json(raw))
        return Session(
            session_id=session_id,
            tracker=tracker,
            next_id=len(items),
            last_used=time.time(),
        )

    def reserve_item_id(self, session_id: str) -> int:
        """Check the session exists, renew it and reserve an item id.

        One atomic script and one round trip. A missing or expired
        session is a KeyError and is never recreated by this call.
        """
        if self._reserve is None:
            self._reserve = self.client.register_script(_RESERVE_SCRIPT)
        number = self._call(lambda: self._reserve(
            keys=[self._key(session_id, part) for part in self.PARTS],
            args=[self._ttl_seconds() or 0],
        ))
        if number < 0:
            raise KeyError(session_id)
        if number > self.max_items:
            raise SessionFull(session_id)
        return int(number)

    def record_item(
        self,
        session_id: str,
        item: ContentItem,
        event: AuditEvent,
    ) -> None:
        """Add a labeled item and its audit event in one round trip."""
        def run() -> None:
            pipe = self.client.pipeline(transaction=False)
            pipe.rpush(self._key(session_id, 'items'), item_to_json(item))
            events = self._key(session_id, 'events')
            pipe.rpush(events, event_to_json(event))
            pipe.ltrim(events, -MAX_EVENTS, -1)
            self._expire_all(pipe, session_id)
            pipe.execute()
        self._call(run)

    def append_event(self, session_id: str, event: AuditEvent) -> None:
        """Add an audit event, keeping the newest MAX_EVENTS."""
        def run() -> None:
            pipe = self.client.pipeline(transaction=False)
            events = self._key(session_id, 'events')
            pipe.rpush(events, event_to_json(event))
            pipe.ltrim(events, -MAX_EVENTS, -1)
            self._expire_all(pipe, session_id)
            pipe.execute()
        self._call(run)

    def events(self, session_id: str) -> list[AuditEvent]:
        """Return the session's audit events; KeyError if missing."""
        self.touch(session_id)
        raw = self._call(lambda: self.client.lrange(
            self._key(session_id, 'events'), 0, -1,
        ))
        return [event_from_json(entry) for entry in raw]

    def purge_expired(self) -> int:
        """Redis expires keys itself, so there is nothing to do."""
        return 0

    def count(self) -> int | None:
        """Counting sessions would scan the keyspace, so it is not offered."""
        return None

    def ping(self) -> bool:
        """True when Redis answers."""
        try:
            return bool(self._call(self.client.ping))
        except StoreUnavailable:
            return False
