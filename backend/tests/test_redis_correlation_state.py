from __future__ import annotations

from datetime import datetime, timezone

import fakeredis

from correlation.redis_state import RedisCorrelationStateStore
from events.models import NormalizedEvent


def _event(event_id: str, port: int = 22) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        event_type="NETWORK_CONNECTION",
        timestamp=datetime.now(timezone.utc),
        source_ip="10.0.0.5",
        destination_ip="10.0.0.10",
        destination_port=port,
        sensor_id="test-sensor",
    )


def test_redis_state_deduplicates_per_tracking_key() -> None:
    client = fakeredis.FakeRedis(decode_responses=True)
    store = RedisCorrelationStateStore(client)
    event = _event("e-1")

    assert store.add_event("rule:a", event, ttl_seconds=60) is True
    assert store.add_event("rule:a", event, ttl_seconds=60) is False
    assert store.add_event("rule:b", event, ttl_seconds=60) is True


def test_redis_state_is_shared_between_store_instances() -> None:
    client = fakeredis.FakeRedis(decode_responses=True)
    first = RedisCorrelationStateStore(client)
    second = RedisCorrelationStateStore(client)

    assert first.add_event("shared", _event("e-1", 22), ttl_seconds=60)
    assert second.add_event("shared", _event("e-2", 23), ttl_seconds=60)

    events = second.get_events("shared", window_seconds=60)
    assert [item.event_id for item in events] == ["e-1", "e-2"]


def test_redis_state_clear_key_removes_window_and_dedupe() -> None:
    client = fakeredis.FakeRedis(decode_responses=True)
    store = RedisCorrelationStateStore(client)
    event = _event("e-1")

    assert store.add_event("clear-me", event, ttl_seconds=60)
    store.clear_key("clear-me")
    assert store.get_events("clear-me", window_seconds=60) == []
    assert store.add_event("clear-me", event, ttl_seconds=60) is True
