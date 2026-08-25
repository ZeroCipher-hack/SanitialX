"""Unit tests for Phase 8 detection rules: PortScan, SSHBruteForce, and Honeypot."""

from __future__ import annotations

from datetime import datetime, timezone
import pytest

from correlation.enums import Severity
from correlation.rules.honeypot import HoneypotDetectionRule
from correlation.rules.port_scan import PortScanDetectionRule
from correlation.rules.ssh_bruteforce import SSHBruteForceDetectionRule
from correlation.state import InMemoryCorrelationStateStore
from events.models import NormalizedEvent


def _make_event(
    event_id: str | None = None,
    src: str = "192.168.1.50",
    dst: str = "10.0.0.1",
    dport: int = 80,
    protocol: str = "TCP",
) -> NormalizedEvent:
    kwargs = {
        "event_type": protocol,
        "timestamp": datetime.now(timezone.utc),
        "sensor_id": "scapy-1",
        "source_ip": src,
        "destination_ip": dst,
        "destination_port": dport,
        "protocol": protocol,
    }
    if event_id:
        kwargs["event_id"] = event_id
    return NormalizedEvent(**kwargs)


class TestPortScanDetectionRule:
    def test_triggers_on_threshold_reached(self) -> None:
        rule = PortScanDetectionRule(distinct_ports_threshold=3, window_seconds=60)
        store = InMemoryCorrelationStateStore()

        # Send 2 events on different ports -> no detection yet
        d1 = rule.evaluate(_make_event(src="1.1.1.1", dport=80), store)
        d2 = rule.evaluate(_make_event(src="1.1.1.1", dport=443), store)
        assert len(d1) == 0
        assert len(d2) == 0

        # Send 3rd event on distinct port -> detection!
        d3 = rule.evaluate(_make_event(src="1.1.1.1", dport=22), store)
        assert len(d3) == 1
        det = d3[0]
        assert det.rule_id == rule.rule_id
        assert det.severity == Severity.HIGH
        assert det.source_ip == "1.1.1.1"
        assert len(det.triggering_event_ids) == 3

    def test_deduplication_prevents_false_trigger(self) -> None:
        """Same event redelivered must not count as distinct/new."""
        rule = PortScanDetectionRule(distinct_ports_threshold=3, window_seconds=60)
        store = InMemoryCorrelationStateStore()

        e1 = _make_event(event_id="e1", src="1.1.1.1", dport=80)
        rule.evaluate(e1, store)
        # Redeliver e1 multiple times
        rule.evaluate(e1, store)
        rule.evaluate(e1, store)

        e2 = _make_event(event_id="e2", src="1.1.1.1", dport=443)
        detections = rule.evaluate(e2, store)
        # Only 2 distinct events registered so far, threshold is 3
        assert len(detections) == 0


class TestSSHBruteForceDetectionRule:
    def test_triggers_on_attempt_threshold(self) -> None:
        rule = SSHBruteForceDetectionRule(attempt_threshold=3, window_seconds=60)
        store = InMemoryCorrelationStateStore()

        d1 = rule.evaluate(_make_event(src="2.2.2.2", dport=22), store)
        d2 = rule.evaluate(_make_event(src="2.2.2.2", dport=22), store)
        assert len(d1) == 0
        assert len(d2) == 0

        d3 = rule.evaluate(_make_event(src="2.2.2.2", dport=22), store)
        assert len(d3) == 1
        det = d3[0]
        assert det.source_ip == "2.2.2.2"
        assert det.context["attempts_count"] == 3

    def test_ignores_non_ssh_ports(self) -> None:
        rule = SSHBruteForceDetectionRule(attempt_threshold=2, window_seconds=60)
        store = InMemoryCorrelationStateStore()

        d1 = rule.evaluate(_make_event(src="2.2.2.2", dport=80), store)
        d2 = rule.evaluate(_make_event(src="2.2.2.2", dport=80), store)
        assert len(d1) == 0
        assert len(d2) == 0


class TestHoneypotDetectionRule:
    def test_triggers_immediately_on_honeypot_port(self) -> None:
        rule = HoneypotDetectionRule(honeypot_ports={31337, 2323})
        store = InMemoryCorrelationStateStore()

        d1 = rule.evaluate(_make_event(src="3.3.3.3", dport=80), store)
        assert len(d1) == 0

        d2 = rule.evaluate(_make_event(src="3.3.3.3", dport=31337), store)
        assert len(d2) == 1
        det = d2[0]
        assert det.severity == Severity.CRITICAL
        assert det.context["honeypot_port"] == 31337

    def test_deduplicates_redelivered_honeypot_event(self) -> None:
        rule = HoneypotDetectionRule(honeypot_ports={31337})
        store = InMemoryCorrelationStateStore()

        e1 = _make_event(event_id="hp-1", src="3.3.3.3", dport=31337)
        d1 = rule.evaluate(e1, store)
        assert len(d1) == 1

        d2 = rule.evaluate(e1, store)
        assert len(d2) == 0
