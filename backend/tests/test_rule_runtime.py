from __future__ import annotations

from datetime import datetime, timezone

from correlation.engine import CorrelationEngine
from correlation.rule_runtime import DetectionRuleRuntimeManager, compile_persisted_rule
from correlation.state import InMemoryCorrelationStateStore
from events.models import NormalizedEvent


def _stored_rule(*, enabled: bool = True) -> dict:
    return {
        "rule_id": "R-CUSTOM-SSH",
        "rule_name": "Custom SSH Threshold",
        "description": "Detect two SSH observations",
        "severity": "HIGH",
        "enabled": enabled,
        "version": 3,
        "parameters": {
            "schema_version": 1,
            "rule_type": "threshold",
            "conditions": [
                {"field": "destination_port", "operator": "eq", "value": 22},
                {"field": "protocol", "operator": "eq", "value": "TCP"},
            ],
            "group_by": "source_ip",
            "threshold": 2,
            "window_seconds": 60,
            "cooldown_seconds": 120,
            "mitre": {"technique_id": "T1110", "technique": "Brute Force"},
        },
    }


def _event(event_id: str, port: int = 22) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        event_type="TCP",
        timestamp=datetime.now(timezone.utc),
        source_ip="8.8.8.8",
        destination_ip="10.0.0.5",
        destination_port=port,
        protocol="TCP",
        sensor_id="test-sensor",
    )


def test_compile_persisted_rule_executes_safe_conditions() -> None:
    rule = compile_persisted_rule(_stored_rule())
    assert rule is not None

    engine = CorrelationEngine(InMemoryCorrelationStateStore(), rules=[rule])
    assert engine.process_event(_event("e1")) == []
    result = engine.process_event(_event("e2"))

    assert len(result) == 1
    detection = result[0]
    assert detection.rule_id == "R-CUSTOM-SSH"
    assert detection.context["runtime_source"] == "persisted_rule"
    assert detection.context["rule_version"] == 3
    assert detection.context["mitre_technique"] == "T1110"


def test_nonmatching_condition_does_not_trigger() -> None:
    rule = compile_persisted_rule(_stored_rule())
    assert rule is not None
    engine = CorrelationEngine(InMemoryCorrelationStateStore(), rules=[rule])

    engine.process_event(_event("e1", port=80))
    assert engine.process_event(_event("e2", port=80)) == []


def test_runtime_manager_upserts_and_disables_rule() -> None:
    engine = CorrelationEngine(InMemoryCorrelationStateStore())
    manager = DetectionRuleRuntimeManager(engine)

    assert manager.apply_rule(_stored_rule()) is True
    assert [rule.rule_id for rule in engine.rules] == ["R-CUSTOM-SSH"]

    replacement = _stored_rule()
    replacement["version"] = 4
    replacement["rule_name"] = "Reconfigured SSH Threshold"
    assert manager.apply_rule(replacement) is True
    assert len(engine.rules) == 1
    assert engine.rules[0].rule_name == "Reconfigured SSH Threshold"

    assert manager.apply_rule(_stored_rule(enabled=False)) is True
    assert engine.rules == []


def test_legacy_metadata_only_rule_is_skipped() -> None:
    legacy = _stored_rule()
    legacy["parameters"] = {"threshold": 5}
    assert compile_persisted_rule(legacy) is None
