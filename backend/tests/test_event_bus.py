"""Unit tests for event_bus: interfaces, RedisEventBus, and import restrictions."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import importlib
import pkgutil

import pytest
import fakeredis.aioredis

from event_bus.base import EventBus, EventPublisher, EventSubscriber
from event_bus.redis_bus import DEFAULT_CONSUMER_GROUP, DEFAULT_STREAM_NAME, RedisEventBus
from events.enums import EventType
from events.models import NormalizedEvent


def _make_event() -> NormalizedEvent:
    return NormalizedEvent(
        event_type=EventType.TCP.value,
        timestamp=datetime.now(timezone.utc),
        sensor_id="sensor-1",
        source_ip="192.168.1.50",
        destination_ip="10.0.0.1",
        source_port=54321,
        destination_port=80,
        protocol="TCP",
    )


class TestEventBusInterfaces:
    def test_cannot_instantiate_abcs(self) -> None:
        with pytest.raises(TypeError):
            EventPublisher()  # type: ignore[abstract]
        with pytest.raises(TypeError):
            EventSubscriber()  # type: ignore[abstract]
        with pytest.raises(TypeError):
            EventBus()  # type: ignore[abstract]


class TestRedisEventBus:
    @pytest.fixture
    async def fake_redis(self):
        client = fakeredis.aioredis.FakeRedis()
        yield client
        await client.aclose()

    @pytest.mark.asyncio
    async def test_publish_and_consume(self, fake_redis) -> None:
        bus = RedisEventBus(fake_redis, poll_block_ms=10, yield_delay_s=0.01)
        event = _make_event()

        await bus.publish(event)

        consumed = []
        async for msg_id, rec_event in bus.consume(consumer_group="test-group", consumer_name="worker-1"):
            consumed.append((msg_id, rec_event))
            await bus.ack("test-group", msg_id)
            break

        assert len(consumed) == 1
        msg_id, rec_event = consumed[0]
        assert rec_event.event_id == event.event_id
        assert rec_event.event_type == "TCP"

    @pytest.mark.asyncio
    async def test_consumer_name_generated(self, fake_redis) -> None:
        bus = RedisEventBus(fake_redis)
        name1 = bus.generate_consumer_name("worker")
        name2 = bus.generate_consumer_name("worker")
        assert name1.startswith("worker-")
        assert name1 != name2

    @pytest.mark.asyncio
    async def test_empty_poll_yields_control(self, fake_redis) -> None:
        bus = RedisEventBus(fake_redis, poll_block_ms=10, yield_delay_s=0.01)

        consumed = []
        async def run_consume():
            async for item in bus.consume(consumer_group="test-group", consumer_name="worker-1"):
                consumed.append(item)
                break

        task = asyncio.create_task(run_consume())
        await asyncio.sleep(0.05)
        # Should not hang or starve loop; task is still waiting since stream is empty
        assert len(consumed) == 0
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    @pytest.mark.asyncio
    async def test_malformed_message_not_xacked(self, fake_redis) -> None:
        bus = RedisEventBus(fake_redis, poll_block_ms=10, yield_delay_s=0.01)

        # Inject malformed data directly into stream
        await fake_redis.xadd(DEFAULT_STREAM_NAME, fields={"data": "invalid json"})

        consumed = []
        async def run_consume():
            async for item in bus.consume(consumer_group="test-group", consumer_name="worker-1"):
                consumed.append(item)

        task = asyncio.create_task(run_consume())
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        # No valid event consumed
        assert len(consumed) == 0

        # Check pending entries in group to verify message was NOT ACK'd
        pending = await fake_redis.xpending(DEFAULT_STREAM_NAME, "test-group")
        assert pending["pending"] == 1


class TestRedisImportRestrictions:
    """HARD RULE: correlation/redis_bus.py (event_bus/redis_bus.py) is the ONLY Redis import site."""

    def test_only_redis_bus_imports_redis(self) -> None:
        import sys

        for module_name in [
            "core.config",
            "core.errors",
            "events.enums",
            "events.models",
            "sensors.base",
            "sensors.manager",
            "sensors.scapy.sensor",
            "normalizers.base",
            "normalizers.registry",
            "normalizers.scapy",
            "pipeline.dispatcher",
            "pipeline.pipeline",
            "event_bus.base",
        ]:
            mod = importlib.import_module(module_name)
            file_content = getattr(mod, "__file__", "")
            if file_content and file_content.endswith(".py"):
                with open(file_content, "r", encoding="utf-8") as f:
                    content = f.read()
                    assert "import redis" not in content, f"{module_name} illegally imports redis"
                    assert "from redis" not in content, f"{module_name} illegally imports redis"
