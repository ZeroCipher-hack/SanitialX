"""Unit tests for pipeline.dispatcher and pipeline.pipeline."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from core.errors import NormalizationError, PipelineError
from events.enums import EventType
from events.models import NormalizedEvent
from normalizers.factory import create_default_registry
from normalizers.registry import NormalizerRegistry
from normalizers.scapy import ScapyNormalizer
from pipeline.dispatcher import Dispatcher
from pipeline.pipeline import EventPublisher, Pipeline, PipelineStats
from sensors.base import RawEvent


# ── Helpers ──────────────────────────────────────────────────────────────

def _raw(protocol: str, **extra: object) -> RawEvent:
    data: dict = {"protocol": protocol, **extra}
    return RawEvent(sensor_id="test-sensor", raw_data=data)


def _tcp_raw(**extra: object) -> RawEvent:
    return _raw(
        "TCP",
        source_ip="192.168.1.1",
        destination_ip="10.0.0.1",
        source_port=12345,
        destination_port=80,
        tcp_flags="S",
        **extra,
    )


def _arp_raw(**extra: object) -> RawEvent:
    return _raw(
        "ARP",
        source_ip="192.168.1.1",
        destination_ip="192.168.1.2",
        arp_op=1,
        source_mac="aa:bb:cc:dd:ee:ff",
        **extra,
    )


# ── Dispatcher tests ────────────────────────────────────────────────────

class TestDispatcher:
    def test_dispatch_tcp_event(self) -> None:
        registry = create_default_registry()
        dispatcher = Dispatcher(registry)
        raw = _tcp_raw()
        event = dispatcher.dispatch(raw)

        assert isinstance(event, NormalizedEvent)
        assert event.event_type == EventType.TCP.value
        assert event.source_ip == "192.168.1.1"

    def test_dispatch_arp_event(self) -> None:
        registry = create_default_registry()
        dispatcher = Dispatcher(registry)
        raw = _arp_raw()
        event = dispatcher.dispatch(raw)

        assert event.event_type == EventType.ARP_OBSERVED.value

    def test_dispatch_unknown_protocol_raises(self) -> None:
        registry = create_default_registry()
        dispatcher = Dispatcher(registry)
        raw = _raw("ALIEN")

        with pytest.raises(NormalizationError, match="No normalizer"):
            dispatcher.dispatch(raw)

    def test_dispatch_empty_registry_raises(self) -> None:
        registry = NormalizerRegistry()  # empty
        dispatcher = Dispatcher(registry)
        raw = _tcp_raw()

        with pytest.raises(NormalizationError, match="No normalizer"):
            dispatcher.dispatch(raw)


# ── PipelineStats tests ─────────────────────────────────────────────────

class TestPipelineStats:
    def test_initial_values(self) -> None:
        stats = PipelineStats()
        snap = stats.snapshot()
        assert snap["events_received"] == 0
        assert snap["events_normalised"] == 0
        assert snap["events_published"] == 0
        assert snap["events_failed"] == 0
        assert snap["last_error"] is None

    def test_increment_received(self) -> None:
        stats = PipelineStats()
        stats.increment_received()
        stats.increment_received()
        assert stats.snapshot()["events_received"] == 2

    def test_increment_normalised(self) -> None:
        stats = PipelineStats()
        stats.increment_normalised()
        assert stats.snapshot()["events_normalised"] == 1

    def test_increment_published(self) -> None:
        stats = PipelineStats()
        stats.increment_published()
        assert stats.snapshot()["events_published"] == 1

    def test_record_failure(self) -> None:
        stats = PipelineStats()
        stats.record_failure("test error")
        snap = stats.snapshot()
        assert snap["events_failed"] == 1
        assert snap["last_error"] == "test error"

    def test_thread_safety(self) -> None:
        """Multiple threads incrementing stats should not corrupt data."""
        import threading

        stats = PipelineStats()
        num_threads = 50
        increments_per_thread = 100

        def worker() -> None:
            for _ in range(increments_per_thread):
                stats.increment_received()

        threads = [threading.Thread(target=worker) for _ in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert stats.snapshot()["events_received"] == num_threads * increments_per_thread


# ── EventPublisher protocol tests ────────────────────────────────────────

class TestEventPublisherProtocol:
    def test_protocol_is_runtime_checkable(self) -> None:
        """EventPublisher must be a runtime-checkable Protocol."""

        class StubPublisher(EventPublisher):
            async def publish(self, event: NormalizedEvent) -> None:
                pass

        assert isinstance(StubPublisher(), EventPublisher)

    def test_non_publisher_does_not_match(self) -> None:

        class NotAPublisher:
            pass

        assert not isinstance(NotAPublisher(), EventPublisher)


# ── Pipeline tests ───────────────────────────────────────────────────────

class TestPipelineProcess:
    async def test_successful_tcp_processing(self) -> None:
        registry = create_default_registry()
        dispatcher = Dispatcher(registry)
        pipeline = Pipeline(dispatcher)

        raw = _tcp_raw()
        event = await pipeline.process(raw)

        assert event is not None
        assert event.event_type == EventType.TCP.value
        assert event.source_ip == "192.168.1.1"

        snap = pipeline.stats.snapshot()
        assert snap["events_received"] == 1
        assert snap["events_normalised"] == 1
        assert snap["events_published"] == 1
        assert snap["events_failed"] == 0

    async def test_successful_arp_processing(self) -> None:
        registry = create_default_registry()
        dispatcher = Dispatcher(registry)
        pipeline = Pipeline(dispatcher)

        raw = _arp_raw()
        event = await pipeline.process(raw)

        assert event is not None
        assert event.event_type == EventType.ARP_OBSERVED.value

    async def test_unknown_protocol_isolated(self) -> None:
        """Malformed events must not crash the pipeline."""
        registry = create_default_registry()
        dispatcher = Dispatcher(registry)
        pipeline = Pipeline(dispatcher)

        raw = _raw("ALIEN")
        event = await pipeline.process(raw)

        assert event is None  # failed, but no exception

        snap = pipeline.stats.snapshot()
        assert snap["events_received"] == 1
        assert snap["events_normalised"] == 0
        assert snap["events_failed"] == 1
        assert snap["last_error"] is not None
        assert "No normalizer" in snap["last_error"]

    async def test_malformed_event_does_not_crash_subsequent(self) -> None:
        """After a failure, the pipeline must continue processing."""
        registry = create_default_registry()
        dispatcher = Dispatcher(registry)
        pipeline = Pipeline(dispatcher)

        # First: bad event
        bad = _raw("ALIEN")
        result1 = await pipeline.process(bad)
        assert result1 is None

        # Second: good event
        good = _tcp_raw()
        result2 = await pipeline.process(good)
        assert result2 is not None
        assert result2.event_type == EventType.TCP.value

        snap = pipeline.stats.snapshot()
        assert snap["events_received"] == 2
        assert snap["events_normalised"] == 1
        assert snap["events_published"] == 1
        assert snap["events_failed"] == 1

    async def test_with_publisher(self) -> None:
        """When a publisher is wired, events are published after normalisation."""
        published_events: list[NormalizedEvent] = []

        class StubPublisher:
            async def publish(self, event: NormalizedEvent) -> None:
                published_events.append(event)

        registry = create_default_registry()
        dispatcher = Dispatcher(registry)
        publisher = StubPublisher()
        pipeline = Pipeline(dispatcher, publisher=publisher)

        raw = _tcp_raw()
        event = await pipeline.process(raw)

        assert event is not None
        assert len(published_events) == 1
        assert published_events[0].event_id == event.event_id

    async def test_publisher_failure_isolated(self) -> None:
        """If the publisher raises, the failure is isolated."""

        class FailingPublisher:
            async def publish(self, event: NormalizedEvent) -> None:
                raise RuntimeError("Redis connection lost")

        registry = create_default_registry()
        dispatcher = Dispatcher(registry)
        pipeline = Pipeline(dispatcher, publisher=FailingPublisher())

        raw = _tcp_raw()
        event = await pipeline.process(raw)

        assert event is None  # isolated failure

        snap = pipeline.stats.snapshot()
        assert snap["events_received"] == 1
        assert snap["events_normalised"] == 1
        assert snap["events_failed"] == 1
        assert "Redis connection lost" in (snap["last_error"] or "")

    async def test_no_publisher_still_succeeds(self) -> None:
        """Without a publisher, events are normalised and validated only."""
        registry = create_default_registry()
        dispatcher = Dispatcher(registry)
        pipeline = Pipeline(dispatcher, publisher=None)

        raw = _tcp_raw()
        event = await pipeline.process(raw)

        assert event is not None
        snap = pipeline.stats.snapshot()
        assert snap["events_published"] == 1  # counted even without publisher

    async def test_multiple_events_stats_accumulate(self) -> None:
        registry = create_default_registry()
        dispatcher = Dispatcher(registry)
        pipeline = Pipeline(dispatcher)

        for _ in range(10):
            await pipeline.process(_tcp_raw())

        snap = pipeline.stats.snapshot()
        assert snap["events_received"] == 10
        assert snap["events_normalised"] == 10
        assert snap["events_published"] == 10
        assert snap["events_failed"] == 0


class TestPipelineWithRealScapyPackets:
    """End-to-end: real Scapy packet → ScapySensor._extract_metadata → Pipeline."""

    @pytest.fixture(autouse=True)
    def _import_scapy(self) -> None:
        pytest.importorskip("scapy")

    async def test_real_tcp_packet_through_pipeline(self) -> None:
        from scapy.layers.inet import IP, TCP
        from sensors.scapy.sensor import ScapySensor

        pkt = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=443, flags="S")
        meta = ScapySensor._extract_metadata(pkt)
        raw = RawEvent(sensor_id="scapy-1", raw_data=meta)

        registry = create_default_registry()
        dispatcher = Dispatcher(registry)
        pipeline = Pipeline(dispatcher)

        event = await pipeline.process(raw)
        assert event is not None
        assert event.event_type == "TCP"
        assert event.destination_port == 443

    async def test_real_arp_packet_through_pipeline(self) -> None:
        from scapy.layers.l2 import ARP, Ether
        from sensors.scapy.sensor import ScapySensor

        pkt = Ether() / ARP(op=1, psrc="192.168.1.1", pdst="192.168.1.2")
        meta = ScapySensor._extract_metadata(pkt)
        raw = RawEvent(sensor_id="scapy-1", raw_data=meta)

        registry = create_default_registry()
        dispatcher = Dispatcher(registry)
        pipeline = Pipeline(dispatcher)

        event = await pipeline.process(raw)
        assert event is not None
        assert event.event_type == "ARP_OBSERVED"
        assert event.event_type != "ARP_SPOOF"
