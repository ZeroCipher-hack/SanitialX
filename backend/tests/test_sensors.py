"""Unit tests for sensors.base, sensors.manager, and sensors.scapy.sensor."""

from __future__ import annotations

import asyncio
import threading
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock

import pytest

from sensors.base import BaseSensor, RawEvent, RawEventCallback
from sensors.manager import SensorManager


# ── RawEvent ─────────────────────────────────────────────────────────────

class TestRawEvent:
    def test_creation(self) -> None:
        evt = RawEvent(sensor_id="test-sensor", raw_data={"protocol": "TCP"})
        assert evt.sensor_id == "test-sensor"
        assert evt.raw_data == {"protocol": "TCP"}
        assert isinstance(evt.timestamp, datetime)
        assert evt.timestamp.tzinfo is not None

    def test_frozen(self) -> None:
        evt = RawEvent(sensor_id="test")
        with pytest.raises(AttributeError):
            evt.sensor_id = "other"  # type: ignore[misc]

    def test_defaults(self) -> None:
        evt = RawEvent(sensor_id="test")
        assert evt.raw_data == {}
        assert evt.timestamp.tzinfo == timezone.utc


# ── Stub sensor for testing BaseSensor / SensorManager ───────────────────

class StubSensor(BaseSensor):
    """Minimal concrete sensor for testing the abstract contract."""

    def __init__(self, sensor_id: str, callback: RawEventCallback) -> None:
        super().__init__(sensor_id=sensor_id, callback=callback)
        self._running = False
        self._started_count = 0
        self._stopped_count = 0

    async def start(self) -> None:
        self._running = True
        self._started_count += 1

    async def stop(self) -> None:
        self._running = False
        self._stopped_count += 1

    def is_running(self) -> bool:
        return self._running

    def health(self) -> dict[str, Any]:
        return {
            "running": self._running,
            "packets_captured": 0,
            "errors": 0,
            "last_error": None,
        }


# ── BaseSensor tests ─────────────────────────────────────────────────────

class TestBaseSensor:
    def test_sensor_id_property(self) -> None:
        cb = AsyncMock()
        sensor = StubSensor("my-sensor", cb)
        assert sensor.sensor_id == "my-sensor"

    async def test_start_stop_lifecycle(self) -> None:
        cb = AsyncMock()
        sensor = StubSensor("s1", cb)
        assert not sensor.is_running()
        await sensor.start()
        assert sensor.is_running()
        await sensor.stop()
        assert not sensor.is_running()

    def test_health_contract(self) -> None:
        cb = AsyncMock()
        sensor = StubSensor("s1", cb)
        h = sensor.health()
        assert "running" in h
        assert "packets_captured" in h
        assert "errors" in h
        assert "last_error" in h


# ── SensorManager tests ─────────────────────────────────────────────────

class TestSensorManager:
    def test_register_and_retrieve(self) -> None:
        mgr = SensorManager()
        cb = AsyncMock()
        sensor = StubSensor("s1", cb)
        mgr.register(sensor)
        assert "s1" in mgr.sensors

    def test_duplicate_registration_raises(self) -> None:
        mgr = SensorManager()
        cb = AsyncMock()
        s1 = StubSensor("s1", cb)
        mgr.register(s1)
        with pytest.raises(ValueError, match="already registered"):
            mgr.register(StubSensor("s1", cb))

    def test_unregister(self) -> None:
        mgr = SensorManager()
        cb = AsyncMock()
        sensor = StubSensor("s1", cb)
        mgr.register(sensor)
        mgr.unregister("s1")
        assert "s1" not in mgr.sensors

    def test_unregister_unknown_raises(self) -> None:
        mgr = SensorManager()
        with pytest.raises(KeyError):
            mgr.unregister("nonexistent")

    async def test_start_all(self) -> None:
        mgr = SensorManager()
        cb = AsyncMock()
        s1 = StubSensor("s1", cb)
        s2 = StubSensor("s2", cb)
        mgr.register(s1)
        mgr.register(s2)
        await mgr.start_all()
        assert s1.is_running()
        assert s2.is_running()

    async def test_stop_all(self) -> None:
        mgr = SensorManager()
        cb = AsyncMock()
        s1 = StubSensor("s1", cb)
        mgr.register(s1)
        await mgr.start_all()
        await mgr.stop_all()
        assert not s1.is_running()

    def test_health_all(self) -> None:
        mgr = SensorManager()
        cb = AsyncMock()
        mgr.register(StubSensor("s1", cb))
        mgr.register(StubSensor("s2", cb))
        health = mgr.health_all()
        assert "s1" in health
        assert "s2" in health


# ── ScapySensor metadata extraction tests ────────────────────────────────

class TestScapySensorMetadataExtraction:
    """Test metadata extraction with real Scapy Packet objects.

    These tests verify architecture invariants #1 and #2:
    - TCP port 22 must NOT produce SSH_LOGIN
    - ARP must produce ARP metadata, NOT ARP_SPOOF
    """

    @pytest.fixture(autouse=True)
    def _import_scapy(self) -> None:
        """Import scapy components — skip if scapy not available."""
        pytest.importorskip("scapy")

    def test_tcp_packet_extraction(self) -> None:
        from scapy.layers.inet import IP, TCP
        from scapy.packet import Packet
        from sensors.scapy.sensor import ScapySensor

        pkt = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=80, flags="S")
        meta = ScapySensor._extract_metadata(pkt)

        assert meta["protocol"] == "TCP"
        assert meta["source_ip"] == "192.168.1.1"
        assert meta["destination_ip"] == "10.0.0.1"
        assert meta["source_port"] == 12345
        assert meta["destination_port"] == 80
        assert "tcp_flags" in meta

    def test_tcp_port_22_is_not_ssh_login(self) -> None:
        """Architecture invariant #2: TCP port 22 ≠ SSH_LOGIN."""
        from scapy.layers.inet import IP, TCP
        from sensors.scapy.sensor import ScapySensor

        pkt = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=54321, dport=22, flags="S")
        meta = ScapySensor._extract_metadata(pkt)

        assert meta["protocol"] == "TCP"
        assert meta["destination_port"] == 22
        # Must NOT contain any SSH-related fabrication
        assert "ssh" not in str(meta).lower() or "ssh" not in meta.get("protocol", "").lower()
        assert meta.get("protocol") == "TCP"  # Not SSH_LOGIN

    def test_arp_packet_extraction(self) -> None:
        """Architecture invariant #1: ARP ≠ ARP_SPOOF."""
        from scapy.layers.l2 import ARP, Ether
        from sensors.scapy.sensor import ScapySensor

        pkt = Ether() / ARP(op=1, psrc="192.168.1.1", pdst="192.168.1.2",
                            hwsrc="aa:bb:cc:dd:ee:ff", hwdst="00:00:00:00:00:00")
        meta = ScapySensor._extract_metadata(pkt)

        assert meta["protocol"] == "ARP"
        assert meta["arp_op"] == 1
        assert meta["source_ip"] == "192.168.1.1"
        assert meta["destination_ip"] == "192.168.1.2"
        assert meta["source_mac"] == "aa:bb:cc:dd:ee:ff"
        # Must NOT contain spoof-related fabrication
        assert "spoof" not in str(meta).lower()

    def test_udp_packet_extraction(self) -> None:
        from scapy.layers.inet import IP, UDP
        from sensors.scapy.sensor import ScapySensor

        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5000, dport=53)
        meta = ScapySensor._extract_metadata(pkt)

        assert meta["protocol"] == "UDP"
        assert meta["source_port"] == 5000
        assert meta["destination_port"] == 53

    def test_icmp_packet_extraction(self) -> None:
        from scapy.layers.inet import IP, ICMP
        from sensors.scapy.sensor import ScapySensor

        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(type=8, code=0)
        meta = ScapySensor._extract_metadata(pkt)

        assert meta["protocol"] == "ICMP"
        assert meta["icmp_type"] == 8
        assert meta["icmp_code"] == 0


# ── ScapySensor thread→asyncio bridge test ───────────────────────────────

class TestScapySensorThreadBridge:
    """Architecture invariant #3: verify thread→asyncio bridge works.

    Invokes the packet handler from a real OS threading.Thread and verifies
    the resulting event reaches the asyncio event loop.
    """

    async def test_packet_handler_from_thread(self) -> None:
        """Simulate Scapy's capture thread calling _on_packet."""
        pytest.importorskip("scapy")
        from scapy.layers.inet import IP, TCP
        from sensors.scapy.sensor import ScapySensor

        received_events: list[RawEvent] = []
        event_received = asyncio.Event()

        async def test_callback(raw_event: RawEvent) -> None:
            received_events.append(raw_event)
            event_received.set()

        sensor = ScapySensor(
            sensor_id="bridge-test",
            callback=test_callback,
            interface="lo",
        )

        # Capture the event loop (normally done in start())
        sensor._loop = asyncio.get_running_loop()

        # Build a test packet
        pkt = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=1111, dport=2222)

        # Call _on_packet from a real OS thread (simulating Scapy's behaviour)
        def thread_target() -> None:
            sensor._on_packet(pkt)

        t = threading.Thread(target=thread_target)
        t.start()
        t.join(timeout=5)

        # Wait for the async callback to fire
        await asyncio.wait_for(event_received.wait(), timeout=5)

        assert len(received_events) == 1
        assert received_events[0].sensor_id == "bridge-test"
        assert received_events[0].raw_data["source_ip"] == "1.2.3.4"
        assert received_events[0].raw_data["protocol"] == "TCP"

    async def test_health_counters_thread_safe(self) -> None:
        """Verify health counters increment correctly from threads."""
        pytest.importorskip("scapy")
        from scapy.layers.inet import IP, TCP
        from sensors.scapy.sensor import ScapySensor

        callback = AsyncMock()
        sensor = ScapySensor(
            sensor_id="counter-test",
            callback=callback,
            interface="lo",
        )
        sensor._loop = asyncio.get_running_loop()

        pkt = IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=1111, dport=2222)

        # Fire multiple packets from multiple threads
        threads = []
        num_packets = 20
        for _ in range(num_packets):
            t = threading.Thread(target=sensor._on_packet, args=(pkt,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=5)

        # Allow async callbacks to complete
        await asyncio.sleep(0.5)

        health = sensor.health()
        assert health["packets_captured"] == num_packets
        assert health["errors"] == 0
