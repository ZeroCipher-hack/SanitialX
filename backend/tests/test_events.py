"""Unit tests for events.enums and events.models."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta

import pytest
from pydantic import ValidationError as PydanticValidationError

from events.enums import EventType
from events.models import NormalizedEvent


# ── EventType Enum ───────────────────────────────────────────────────────

class TestEventType:
    def test_observation_types_exist(self) -> None:
        assert EventType.TCP == "TCP"
        assert EventType.UDP == "UDP"
        assert EventType.ICMP == "ICMP"
        assert EventType.ARP_OBSERVED == "ARP_OBSERVED"
        assert EventType.DNS_QUERY == "DNS_QUERY"

    def test_detection_types_exist(self) -> None:
        assert EventType.SSH_LOGIN == "SSH_LOGIN"
        assert EventType.ARP_SPOOF == "ARP_SPOOF"
        assert EventType.PORT_SCAN == "PORT_SCAN"

    def test_arp_observed_is_not_arp_spoof(self) -> None:
        """Architecture invariant #1."""
        assert EventType.ARP_OBSERVED != EventType.ARP_SPOOF

    def test_unknown_type_exists(self) -> None:
        assert EventType.UNKNOWN == "UNKNOWN"

    def test_unique_values(self) -> None:
        values = [e.value for e in EventType]
        assert len(values) == len(set(values))


# ── NormalizedEvent ──────────────────────────────────────────────────────

def _make_event(**overrides) -> NormalizedEvent:
    """Helper to create a valid NormalizedEvent with sensible defaults."""
    defaults = dict(
        event_type=EventType.TCP.value,
        timestamp=datetime.now(timezone.utc),
        source_ip="192.168.1.1",
        destination_ip="10.0.0.1",
        source_port=12345,
        destination_port=80,
        protocol="TCP",
        sensor_id="scapy-sensor-1",
    )
    defaults.update(overrides)
    return NormalizedEvent(**defaults)


class TestNormalizedEventCreation:
    def test_valid_creation(self) -> None:
        event = _make_event()
        assert event.event_type == "TCP"
        assert event.source_ip == "192.168.1.1"
        assert event.sensor_id == "scapy-sensor-1"

    def test_event_id_auto_generated(self) -> None:
        event = _make_event()
        assert event.event_id is not None
        # Must be a valid UUID4
        parsed = uuid.UUID(event.event_id)
        assert parsed.version == 4

    def test_event_id_unique_per_instance(self) -> None:
        e1 = _make_event()
        e2 = _make_event()
        assert e1.event_id != e2.event_id

    def test_event_id_can_be_supplied(self) -> None:
        custom_id = str(uuid.uuid4())
        event = _make_event(event_id=custom_id)
        assert event.event_id == custom_id

    def test_metadata_defaults_to_empty_dict(self) -> None:
        event = _make_event()
        assert event.metadata == {}

    def test_metadata_accepted(self) -> None:
        event = _make_event(metadata={"flags": "SYN", "ttl": 64})
        assert event.metadata == {"flags": "SYN", "ttl": 64}

    def test_optional_fields_default_to_none(self) -> None:
        event = NormalizedEvent(
            event_type="TCP",
            timestamp=datetime.now(timezone.utc),
            sensor_id="test",
        )
        assert event.source_ip is None
        assert event.destination_ip is None
        assert event.source_port is None
        assert event.destination_port is None
        assert event.protocol is None


class TestNormalizedEventImmutability:
    """NormalizedEvent must be frozen — no field mutation allowed."""

    def test_cannot_set_event_type(self) -> None:
        event = _make_event()
        with pytest.raises(PydanticValidationError):
            event.event_type = "UDP"  # type: ignore[misc]

    def test_cannot_set_event_id(self) -> None:
        event = _make_event()
        with pytest.raises(PydanticValidationError):
            event.event_id = "new-id"  # type: ignore[misc]

    def test_cannot_set_timestamp(self) -> None:
        event = _make_event()
        with pytest.raises(PydanticValidationError):
            event.timestamp = datetime.now(timezone.utc)  # type: ignore[misc]

    def test_cannot_set_source_ip(self) -> None:
        event = _make_event()
        with pytest.raises(PydanticValidationError):
            event.source_ip = "1.2.3.4"  # type: ignore[misc]

    def test_cannot_set_sensor_id(self) -> None:
        event = _make_event()
        with pytest.raises(PydanticValidationError):
            event.sensor_id = "other"  # type: ignore[misc]


class TestNormalizedEventTimestamp:
    """Timestamp must be timezone-aware (UTC). Naive datetimes rejected."""

    def test_naive_timestamp_rejected(self) -> None:
        with pytest.raises(PydanticValidationError, match="[Tt]imezone"):
            _make_event(timestamp=datetime(2025, 1, 1, 12, 0, 0))

    def test_utc_timestamp_accepted(self) -> None:
        ts = datetime(2025, 6, 15, 10, 30, 0, tzinfo=timezone.utc)
        event = _make_event(timestamp=ts)
        assert event.timestamp == ts

    def test_non_utc_aware_normalised_to_utc(self) -> None:
        """Timezone-aware but non-UTC timestamps should be normalised to UTC."""
        est = timezone(timedelta(hours=-5))
        ts = datetime(2025, 6, 15, 10, 0, 0, tzinfo=est)
        event = _make_event(timestamp=ts)
        assert event.timestamp.tzinfo == timezone.utc
        assert event.timestamp == ts.astimezone(timezone.utc)


class TestNormalizedEventValidation:
    """Required fields must be present."""

    def test_missing_event_type_fails(self) -> None:
        with pytest.raises(PydanticValidationError):
            NormalizedEvent(
                timestamp=datetime.now(timezone.utc),
                sensor_id="test",
            )  # type: ignore[call-arg]

    def test_missing_timestamp_fails(self) -> None:
        with pytest.raises(PydanticValidationError):
            NormalizedEvent(
                event_type="TCP",
                sensor_id="test",
            )  # type: ignore[call-arg]

    def test_missing_sensor_id_fails(self) -> None:
        with pytest.raises(PydanticValidationError):
            NormalizedEvent(
                event_type="TCP",
                timestamp=datetime.now(timezone.utc),
            )  # type: ignore[call-arg]


class TestNoDomainInfrastructureImports:
    """events/ must be pure domain — no infrastructure imports."""

    def test_models_no_infra_imports(self) -> None:
        import importlib
        import inspect

        mod = importlib.import_module("events.models")
        source = inspect.getsource(mod)
        for forbidden in ("redis", "fastapi", "scapy", "sqlalchemy", "psycopg"):
            assert f"import {forbidden}" not in source

    def test_enums_no_infra_imports(self) -> None:
        import importlib
        import inspect

        mod = importlib.import_module("events.enums")
        source = inspect.getsource(mod)
        for forbidden in ("redis", "fastapi", "scapy", "sqlalchemy", "psycopg"):
            assert f"import {forbidden}" not in source
