"""Redis-backed correlation state store.

The store receives a synchronous Redis-compatible client via dependency injection.
CorrelationWorker runs the synchronous engine inside ``asyncio.to_thread`` so Redis
I/O never blocks the application's event loop.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from correlation.state import CorrelationStateStore
from events.models import NormalizedEvent


class RedisCorrelationStateStore(CorrelationStateStore):
    """Distributed sliding-window state shared across correlation workers."""

    def __init__(self, redis_client: Any, namespace: str = "sentinelx:corr") -> None:
        self._redis = redis_client
        self._namespace = namespace.rstrip(":")
        self._index_key = f"{self._namespace}:index"

    def _keys(self, key: str) -> tuple[str, str, str]:
        base = f"{self._namespace}:state:{key}"
        return f"{base}:events", f"{base}:payloads", f"{base}:dedupe"

    def _dedupe_key(self, key: str, event_id: str) -> str:
        return f"{self._namespace}:seen:{key}:{event_id}"

    def add_event(self, key: str, event: NormalizedEvent, ttl_seconds: float) -> bool:
        ttl_ms = max(1, int(ttl_seconds * 1000))
        events_key, payloads_key, dedupe_set_key = self._keys(key)
        dedupe_key = self._dedupe_key(key, event.event_id)

        # WATCH/MULTI keeps dedupe + event persistence atomic without Lua and is
        # compatible with standard Redis transaction semantics.
        while True:
            pipe = self._redis.pipeline()
            try:
                pipe.watch(dedupe_key)
                if pipe.exists(dedupe_key):
                    pipe.unwatch()
                    return False

                pipe.multi()
                pipe.set(dedupe_key, "1", px=ttl_ms)
                pipe.zadd(events_key, {event.event_id: event.timestamp.timestamp()})
                pipe.hset(payloads_key, event.event_id, event.model_dump_json())
                pipe.sadd(dedupe_set_key, dedupe_key)
                pipe.sadd(self._index_key, key)
                pipe.pexpire(events_key, ttl_ms)
                pipe.pexpire(payloads_key, ttl_ms)
                pipe.pexpire(dedupe_set_key, ttl_ms)
                pipe.execute()
                return True
            except Exception as exc:
                if exc.__class__.__name__ == "WatchError":
                    continue
                raise
            finally:
                try:
                    pipe.reset()
                except Exception:
                    pass

    def get_events(self, key: str, window_seconds: float) -> list[NormalizedEvent]:
        events_key, payloads_key, _ = self._keys(key)
        now = datetime.now(timezone.utc).timestamp()
        cutoff = now - window_seconds
        event_ids = self._redis.zrangebyscore(events_key, cutoff, "+inf") or []
        if not event_ids:
            return []

        payloads = self._redis.hmget(payloads_key, event_ids)
        events: list[NormalizedEvent] = []
        for payload in payloads:
            if payload:
                events.append(NormalizedEvent.model_validate_json(payload))
        events.sort(key=lambda item: item.timestamp)
        return events

    def clear_key(self, key: str) -> None:
        events_key, payloads_key, dedupe_set_key = self._keys(key)
        dedupe_keys = list(self._redis.smembers(dedupe_set_key) or [])
        pipe = self._redis.pipeline(transaction=True)
        if dedupe_keys:
            pipe.delete(*dedupe_keys)
        pipe.delete(events_key, payloads_key, dedupe_set_key)
        pipe.srem(self._index_key, key)
        pipe.execute()

    def cleanup_expired(self) -> int:
        removed = 0
        keys = list(self._redis.smembers(self._index_key) or [])
        for key in keys:
            events_key, payloads_key, dedupe_set_key = self._keys(str(key))
            if int(self._redis.zcard(events_key) or 0) == 0:
                dedupe_keys = list(self._redis.smembers(dedupe_set_key) or [])
                pipe = self._redis.pipeline(transaction=True)
                if dedupe_keys:
                    pipe.delete(*dedupe_keys)
                pipe.delete(events_key, payloads_key, dedupe_set_key)
                pipe.srem(self._index_key, key)
                pipe.execute()
                removed += 1
        return removed
