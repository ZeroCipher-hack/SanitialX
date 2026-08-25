"""Unit tests for Phase 7 correlation models, state store, and rule abstraction."""

from __future__ import annotations

import importlib
import inspect
from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from correlation.enums import Severity
from correlation.models import Detection
from correlation.rules.base import DetectionRule
from correlation.state import CorrelationStateStore, InMemoryCorrelationStateStore
from events.models import NormalizedEvent


def _make_event(event_id: str | None = None, src: str = "192.168.1.100") -> NormalizedEvent:
    kwargs = {
        "event_type": "TCP",
        "timestamp": datetime.now(timezone.utc),
        "sensor_id": "test-sensor",
        "source_ip": src,
        "destination_ip": "10.0.0.1",
        "destination_port": 80,
    }
    if event_id:
        kwargs["event_id"] = event_id
    return NormalizedEvent(**kwargs)


class TestCorrelationEnumsAndModels:
    def test_severity_values(self) -> None:
        assert Severity.LOW == "LOW"
        assert Severity.MEDIUM == "MEDIUM"
        assert Severity.HIGH == "HIGH"
        assert Severity.CRITICAL == "CRITICAL"

    def test_detection_model_creation(self) -> None:
        d = Detection(
            rule_id="RULE-01",
            rule_name="Test Rule",
            severity=Severity.HIGH,
            title="Test Detection",
            description="Test Description",
            source_ip="192.168.1.10",
        )
        assert d.detection_id is not None
        assert d.severity == Severity.HIGH
        assert d.source_ip == "192.168.1.10"
        assert d.timestamp.tzinfo is timezone.utc

    def test_detection_immutability(self) -> None:
        d = Detection(
            rule_id="RULE-01",
            rule_name="Test Rule",
            severity=Severity.HIGH,
            title="Test Detection",
            description="Test Description",
        )
        with pytest.raises(ValidationError):
            d.severity = Severity.LOW  # type: ignore[misc]

    def test_naive_detection_timestamp_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Detection(
                rule_id="R1",
                rule_name="R",
                severity=Severity.LOW,
                title="T",
                description="D",
                timestamp=datetime.now(),  # naive
            )


class TestInMemoryCorrelationStateStore:
    def test_add_and_get_events(self) -> None:
        store = InMemoryCorrelationStateStore()
        e1 = _make_event("e1", "192.168.1.1")
        e2 = _make_event("e2", "192.168.1.1")

        added1 = store.add_event("192.168.1.1", e1, ttl_seconds=60)
        added2 = store.add_event("192.168.1.1", e2, ttl_seconds=60)

        assert added1 is True
        assert added2 is True

        events = store.get_events("192.168.1.1", window_seconds=300)
        assert len(events) == 2
        assert events[0].event_id == "e1"
        assert events[1].event_id == "e2"

    def test_deduplication_by_event_id(self) -> None:
        """Redis Streams redelivery must not double-count events."""
        store = InMemoryCorrelationStateStore()
        e1 = _make_event("e1", "192.168.1.1")

        added_first = store.add_event("192.168.1.1", e1, ttl_seconds=60)
        added_duplicate = store.add_event("192.168.1.1", e1, ttl_seconds=60)

        assert added_first is True
        assert added_duplicate is False

        events = store.get_events("192.168.1.1", window_seconds=300)
        assert len(events) == 1

    def test_cleanup_expired(self) -> None:
        store = InMemoryCorrelationStateStore(default_ttl_seconds=0.01)
        e1 = _make_event("e1", "10.0.0.5")
        store.add_event("10.0.0.5", e1, ttl_seconds=0.01)

        import time
        time.sleep(0.02)

        removed = store.cleanup_expired()
        assert removed >= 1
        assert len(store.get_events("10.0.0.5", window_seconds=60)) == 0


class TestNoDomainInfraImportsInCorrelation:
    def test_no_infra_imports(self) -> None:
        for module_name in [
            "correlation.enums",
            "correlation.models",
            "correlation.state",
            "correlation.rules.base",
        ]:
            mod = importlib.import_module(module_name)
            source = inspect.getsource(mod)
            for forbidden in ("redis", "fastapi", "scapy", "sqlalchemy", "psycopg"):
                assert f"import {forbidden}" not in source, f"{module_name} illegally imports {forbidden}"
                assert f"from {forbidden}" not in source, f"{module_name} illegally imports {forbidden}"
