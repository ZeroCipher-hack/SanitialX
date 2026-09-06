from __future__ import annotations

from datetime import datetime, timedelta, timezone

from correlation.engine import CorrelationEngine
from correlation.enums import Severity
from correlation.models import Detection
from correlation.rules.threshold_window import ThresholdWindowRule
from correlation.scoring import score_detection
from correlation.sequence import DetectionSequenceRule, SequenceStage
from correlation.state import InMemoryCorrelationStateStore
from events.models import NormalizedEvent


def _detection(*, severity: Severity = Severity.HIGH, seconds: int = 0) -> Detection:
    return Detection(
        rule_id="RULE-X",
        rule_name="Rule X",
        severity=severity,
        title="X",
        description="X",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds),
        source_ip="1.2.3.4",
        triggering_event_ids=["e1", "e2", "e3"],
        context={"threshold": 3, "event_count": 3, "mitre_technique": "T1110"},
    )


def test_score_detection_is_deterministic_and_bounded() -> None:
    scored = score_detection(_detection())
    assert scored.context["scoring_model"] == "deterministic-v1"
    assert 0 <= scored.context["risk_score"] <= 100
    assert 0 <= scored.context["confidence_score"] <= 100
    assert scored.context["risk_score"] == score_detection(_detection()).context["risk_score"]


def _event(event_id: str, seconds: int) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        event_type="AUTH_FAILURE",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds),
        source_ip="5.5.5.5",
        destination_ip="10.0.0.1",
        sensor_id="sensor",
    )


def _single_event_rule(rule_id: str, cooldown: float) -> ThresholdWindowRule:
    return ThresholdWindowRule(
        rule_id=rule_id,
        rule_name=rule_id,
        threshold=1,
        window_seconds=60,
        severity=Severity.HIGH,
        predicate=lambda _event: True,
        group_by=lambda event: event.source_ip,
        title=rule_id,
        description=rule_id,
        clear_on_trigger=True,
        cooldown_seconds=cooldown,
    )


def test_engine_suppresses_repeat_detection_inside_cooldown() -> None:
    engine = CorrelationEngine(
        InMemoryCorrelationStateStore(),
        rules=[_single_event_rule("RULE-A", cooldown=120)],
    )
    first = engine.process_event(_event("e1", 0))
    second = engine.process_event(_event("e2", 30))

    assert len(first) == 1
    assert second == []
    assert first[0].context["risk_score"] >= 70
    assert engine.get_metrics()["suppressed_detections"] == 1


def test_suppressed_primary_detection_still_advances_sequence() -> None:
    engine = CorrelationEngine(
        InMemoryCorrelationStateStore(),
        rules=[
            _single_event_rule("RULE-A", cooldown=120),
            ThresholdWindowRule(
                rule_id="RULE-B",
                rule_name="RULE-B",
                threshold=1,
                window_seconds=60,
                severity=Severity.HIGH,
                predicate=lambda event: event.event_type == "AUTH_FAILURE" and event.metadata.get("stage") == "b",
                group_by=lambda event: event.source_ip,
                title="B",
                description="B",
                cooldown_seconds=120,
            ),
        ],
        sequence_rules=[
            DetectionSequenceRule(
                rule_id="RULE-SEQUENCE",
                rule_name="A then B",
                stages=[SequenceStage("RULE-A", "A"), SequenceStage("RULE-B", "B")],
                window_seconds=300,
            )
        ],
    )

    engine.process_event(_event("a1", 0))
    # RULE-A fires again here but is suppressed; it must still be visible to sequence logic.
    engine.process_event(_event("a2", 10))
    b_event = _event("b1", 20).model_copy(update={"metadata": {"stage": "b"}})
    result = engine.process_event(b_event)

    assert any(item.rule_id == "RULE-SEQUENCE" for item in result)
