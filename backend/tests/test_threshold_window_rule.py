from datetime import datetime, timedelta, timezone

from correlation.enums import Severity
from correlation.rules.threshold_window import ThresholdWindowRule
from correlation.state import InMemoryCorrelationStateStore
from events.models import NormalizedEvent


def _event(event_id: str, ts: datetime, source_ip: str = "10.0.0.5") -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        event_type="AUTH_FAILURE",
        timestamp=ts,
        source_ip=source_ip,
        destination_ip="10.0.0.10",
        destination_port=22,
        protocol="TCP",
        sensor_id="test-sensor",
        metadata={"outcome": "failed", "username": "root"},
    )


def _rule(
    threshold: int = 3,
    window_seconds: float = 300,
    rule_id: str = "auth.bruteforce.generic",
) -> ThresholdWindowRule:
    return ThresholdWindowRule(
        rule_id=rule_id,
        rule_name="Repeated Authentication Failures",
        threshold=threshold,
        window_seconds=window_seconds,
        severity=Severity.HIGH,
        predicate=lambda event: event.event_type == "AUTH_FAILURE"
        and event.metadata.get("outcome") == "failed",
        group_by=lambda event: event.source_ip,
        title="Possible brute-force activity",
        description="Repeated failed authentication events exceeded the configured threshold.",
        mitre_technique="T1110",
    )


def test_threshold_rule_triggers_on_nth_matching_event() -> None:
    store = InMemoryCorrelationStateStore()
    rule = _rule(threshold=3)
    now = datetime.now(timezone.utc)

    assert rule.evaluate(_event("e1", now), store) == []
    assert rule.evaluate(_event("e2", now + timedelta(seconds=10)), store) == []

    detections = rule.evaluate(_event("e3", now + timedelta(seconds=20)), store)

    assert len(detections) == 1
    detection = detections[0]
    assert detection.rule_id == "auth.bruteforce.generic"
    assert detection.severity == Severity.HIGH
    assert detection.triggering_event_ids == ["e1", "e2", "e3"]
    assert detection.context["threshold"] == 3
    assert detection.context["window_seconds"] == 300
    assert detection.context["group"] == "10.0.0.5"
    assert detection.context["mitre_technique"] == "T1110"


def test_threshold_rule_groups_sources_independently() -> None:
    store = InMemoryCorrelationStateStore()
    rule = _rule(threshold=2)
    now = datetime.now(timezone.utc)

    assert rule.evaluate(_event("a1", now, "10.0.0.1"), store) == []
    assert rule.evaluate(_event("b1", now, "10.0.0.2"), store) == []

    detections = rule.evaluate(_event("a2", now + timedelta(seconds=1), "10.0.0.1"), store)
    assert len(detections) == 1
    assert detections[0].context["group"] == "10.0.0.1"


def test_threshold_rule_deduplicates_event_ids_within_same_rule_key() -> None:
    store = InMemoryCorrelationStateStore()
    rule = _rule(threshold=2)
    now = datetime.now(timezone.utc)
    duplicate = _event("same", now)

    assert rule.evaluate(duplicate, store) == []
    assert rule.evaluate(duplicate, store) == []


def test_same_event_can_participate_in_multiple_rules() -> None:
    store = InMemoryCorrelationStateStore()
    first_rule = _rule(threshold=1, rule_id="auth.rule.one")
    second_rule = _rule(threshold=1, rule_id="auth.rule.two")
    event = _event("shared-event", datetime.now(timezone.utc))

    first = first_rule.evaluate(event, store)
    second = second_rule.evaluate(event, store)

    assert len(first) == 1
    assert len(second) == 1
    assert first[0].rule_id == "auth.rule.one"
    assert second[0].rule_id == "auth.rule.two"


def test_threshold_rule_ignores_non_matching_events() -> None:
    store = InMemoryCorrelationStateStore()
    rule = _rule(threshold=1)
    now = datetime.now(timezone.utc)
    event = NormalizedEvent(
        event_id="ok",
        event_type="AUTH_SUCCESS",
        timestamp=now,
        source_ip="10.0.0.5",
        sensor_id="test-sensor",
        metadata={"outcome": "success"},
    )

    assert rule.evaluate(event, store) == []


def test_threshold_rule_validates_configuration() -> None:
    try:
        _rule(threshold=0)
    except ValueError as exc:
        assert "threshold" in str(exc)
    else:
        raise AssertionError("threshold=0 should fail")
