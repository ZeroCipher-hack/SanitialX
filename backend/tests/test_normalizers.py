"""Unit tests for normalizers: base, registry, factory, and ScapyNormalizer."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from core.errors import NormalizationError
from events.enums import EventType
from events.models import NormalizedEvent
from normalizers.base import BaseNormalizer
from normalizers.factory import create_default_registry
from normalizers.registry import NormalizerRegistry
from normalizers.scapy import ScapyNormalizer
from sensors.base import RawEvent


# ── Helpers ──────────────────────────────────────────────────────────────

def _raw(protocol: str, **extra: object) -> RawEvent:
    """Build a RawEvent with the given protocol and optional extra data."""
    data: dict = {"protocol": protocol, **extra}
    return RawEvent(
        sensor_id="test-sensor",
        timestamp=datetime.now(timezone.utc),
        raw_data=data,
    )


# ── BaseNormalizer contract ──────────────────────────────────────────────

class TestBaseNormalizerContract:
    def test_cannot_instantiate_directly(self) -> None:
        with pytest.raises(TypeError):
            BaseNormalizer()  # type: ignore[abstract]

    def test_single_canonical_class(self) -> None:
        """There must be exactly one BaseNormalizer in the codebase."""
        assert BaseNormalizer.__module__ == "normalizers.base"


# ── NormalizerRegistry ───────────────────────────────────────────────────

class TestNormalizerRegistry:
    def test_register_and_lookup(self) -> None:
        registry = NormalizerRegistry()
        normalizer = ScapyNormalizer()
        registry.register(normalizer)

        raw = _raw("TCP", source_ip="1.2.3.4", destination_ip="5.6.7.8",
                    source_port=1111, destination_port=80)
        found = registry.get_normalizer(raw)
        assert found is normalizer

    def test_no_match_returns_none(self) -> None:
        registry = NormalizerRegistry()
        registry.register(ScapyNormalizer())
        raw = _raw("UNKNOWN_PROTO")
        assert registry.get_normalizer(raw) is None

    def test_empty_registry_returns_none(self) -> None:
        registry = NormalizerRegistry()
        raw = _raw("TCP")
        assert registry.get_normalizer(raw) is None

    def test_normalizers_property(self) -> None:
        registry = NormalizerRegistry()
        n = ScapyNormalizer()
        registry.register(n)
        assert registry.normalizers == [n]


# ── Factory ──────────────────────────────────────────────────────────────

class TestNormalizerFactory:
    def test_default_registry_contains_scapy(self) -> None:
        registry = create_default_registry()
        assert len(registry.normalizers) == 1
        assert isinstance(registry.normalizers[0], ScapyNormalizer)


# ── ScapyNormalizer ──────────────────────────────────────────────────────

class TestScapyNormalizerCanHandle:
    @pytest.mark.parametrize("protocol", ["TCP", "UDP", "ICMP", "ARP"])
    def test_handles_known_protocols(self, protocol: str) -> None:
        normalizer = ScapyNormalizer()
        raw = _raw(protocol)
        assert normalizer.can_handle(raw) is True

    def test_rejects_unknown_protocol(self) -> None:
        normalizer = ScapyNormalizer()
        raw = _raw("ALIEN")
        assert normalizer.can_handle(raw) is False

    def test_rejects_empty_protocol(self) -> None:
        normalizer = ScapyNormalizer()
        raw = RawEvent(sensor_id="test", raw_data={})
        assert normalizer.can_handle(raw) is False


class TestScapyNormalizerNormalize:
    def test_tcp_produces_tcp_event(self) -> None:
        normalizer = ScapyNormalizer()
        raw = _raw("TCP", source_ip="192.168.1.1", destination_ip="10.0.0.1",
                    source_port=12345, destination_port=80, tcp_flags="S")
        event = normalizer.normalize(raw)

        assert isinstance(event, NormalizedEvent)
        assert event.event_type == EventType.TCP.value
        assert event.source_ip == "192.168.1.1"
        assert event.destination_ip == "10.0.0.1"
        assert event.source_port == 12345
        assert event.destination_port == 80
        assert event.protocol == "TCP"
        assert event.sensor_id == "test-sensor"
        assert event.metadata.get("tcp_flags") == "S"

    def test_arp_produces_arp_observed(self) -> None:
        """Architecture invariant #1: ARP → ARP_OBSERVED, NOT ARP_SPOOF."""
        normalizer = ScapyNormalizer()
        raw = _raw("ARP", source_ip="192.168.1.1", destination_ip="192.168.1.2",
                    arp_op=1, source_mac="aa:bb:cc:dd:ee:ff")
        event = normalizer.normalize(raw)

        assert event.event_type == EventType.ARP_OBSERVED.value
        assert event.event_type != EventType.ARP_SPOOF.value
        assert event.source_ip == "192.168.1.1"
        assert event.protocol == "ARP"

    def test_tcp_port_22_is_not_ssh_login(self) -> None:
        """Architecture invariant #2: TCP port 22 → TCP, NOT SSH_LOGIN."""
        normalizer = ScapyNormalizer()
        raw = _raw("TCP", source_ip="192.168.1.1", destination_ip="10.0.0.1",
                    source_port=54321, destination_port=22, tcp_flags="S")
        event = normalizer.normalize(raw)

        assert event.event_type == EventType.TCP.value
        assert event.event_type != EventType.SSH_LOGIN.value
        assert event.destination_port == 22

    def test_udp_produces_udp_event(self) -> None:
        normalizer = ScapyNormalizer()
        raw = _raw("UDP", source_ip="10.0.0.1", destination_ip="10.0.0.2",
                    source_port=5000, destination_port=53)
        event = normalizer.normalize(raw)

        assert event.event_type == EventType.UDP.value
        assert event.protocol == "UDP"

    def test_icmp_produces_icmp_event(self) -> None:
        normalizer = ScapyNormalizer()
        raw = _raw("ICMP", source_ip="10.0.0.1", destination_ip="10.0.0.2",
                    icmp_type=8, icmp_code=0)
        event = normalizer.normalize(raw)

        assert event.event_type == EventType.ICMP.value
        assert event.protocol == "ICMP"
        assert event.metadata.get("icmp_type") == 8

    def test_unknown_protocol_raises(self) -> None:
        normalizer = ScapyNormalizer()
        raw = _raw("ALIEN")
        with pytest.raises(NormalizationError, match="cannot handle"):
            normalizer.normalize(raw)

    def test_event_id_auto_generated(self) -> None:
        normalizer = ScapyNormalizer()
        raw = _raw("TCP", source_ip="1.2.3.4", destination_ip="5.6.7.8",
                    source_port=1111, destination_port=2222)
        event = normalizer.normalize(raw)
        assert event.event_id is not None
        assert len(event.event_id) > 0

    def test_timestamp_preserved_from_raw(self) -> None:
        ts = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        raw = RawEvent(sensor_id="test", timestamp=ts,
                       raw_data={"protocol": "TCP", "source_ip": "1.1.1.1",
                                 "destination_ip": "2.2.2.2"})
        normalizer = ScapyNormalizer()
        event = normalizer.normalize(raw)
        assert event.timestamp == ts

    def test_normalized_event_is_immutable(self) -> None:
        normalizer = ScapyNormalizer()
        raw = _raw("TCP", source_ip="1.2.3.4", destination_ip="5.6.7.8",
                    source_port=1111, destination_port=2222)
        event = normalizer.normalize(raw)
        with pytest.raises(Exception):
            event.event_type = "UDP"  # type: ignore[misc]


class TestScapyNormalizerWithRealScapyPackets:
    """Integration: ScapySensor._extract_metadata → ScapyNormalizer.normalize."""

    @pytest.fixture(autouse=True)
    def _import_scapy(self) -> None:
        pytest.importorskip("scapy")

    def test_real_tcp_packet_pipeline(self) -> None:
        from scapy.layers.inet import IP, TCP
        from sensors.scapy.sensor import ScapySensor

        pkt = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=12345, dport=443, flags="S")
        meta = ScapySensor._extract_metadata(pkt)
        raw = RawEvent(sensor_id="scapy-1", raw_data=meta)

        normalizer = ScapyNormalizer()
        event = normalizer.normalize(raw)

        assert event.event_type == "TCP"
        assert event.source_ip == "192.168.1.1"
        assert event.destination_port == 443

    def test_real_arp_packet_pipeline(self) -> None:
        from scapy.layers.l2 import ARP, Ether
        from sensors.scapy.sensor import ScapySensor

        pkt = Ether() / ARP(op=1, psrc="192.168.1.1", pdst="192.168.1.2",
                            hwsrc="aa:bb:cc:dd:ee:ff")
        meta = ScapySensor._extract_metadata(pkt)
        raw = RawEvent(sensor_id="scapy-1", raw_data=meta)

        normalizer = ScapyNormalizer()
        event = normalizer.normalize(raw)

        assert event.event_type == "ARP_OBSERVED"
        assert event.event_type != "ARP_SPOOF"
        assert event.source_ip == "192.168.1.1"

    def test_real_tcp_port_22_not_ssh(self) -> None:
        """End-to-end invariant #2 check with real packet."""
        from scapy.layers.inet import IP, TCP
        from sensors.scapy.sensor import ScapySensor

        pkt = IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=54321, dport=22, flags="S")
        meta = ScapySensor._extract_metadata(pkt)
        raw = RawEvent(sensor_id="scapy-1", raw_data=meta)

        normalizer = ScapyNormalizer()
        event = normalizer.normalize(raw)

        assert event.event_type == "TCP"
        assert event.event_type != "SSH_LOGIN"
        assert event.destination_port == 22


class TestNoDuplicateNormalizerAbstraction:
    """Verify there is no second normalizer contract under events/."""

    def test_no_events_normalizer_module(self) -> None:
        """Architecture §3 resolution #1: events/normalizer.py must not exist."""
        import importlib

        with pytest.raises(ModuleNotFoundError):
            importlib.import_module("events.normalizer")
