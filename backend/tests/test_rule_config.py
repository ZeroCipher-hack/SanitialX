from __future__ import annotations

import pytest
from pydantic import ValidationError

from api.schemas import DetectionRuleUpdate
from correlation.enums import Severity
from correlation.rule_config import validate_rule_parameters


def test_valid_threshold_rule_parameters_are_normalized() -> None:
    params = validate_rule_parameters(
        {
            "schema_version": 1,
            "rule_type": "threshold",
            "conditions": [
                {"field": "event_type", "operator": "eq", "value": "AUTH_FAILURE"},
                {"field": "destination_port", "operator": "in", "value": [22, 2222]},
            ],
            "group_by": "source_ip",
            "threshold": 5,
            "window_seconds": 60,
            "cooldown_seconds": 120,
            "mitre": {
                "tactic": "Credential Access",
                "technique_id": "T1110",
                "technique": "Brute Force",
            },
        }
    )
    assert params["schema_version"] == 1
    assert params["rule_type"] == "threshold"
    assert params["threshold"] == 5


def test_distinct_threshold_requires_distinct_by() -> None:
    with pytest.raises(ValidationError, match="distinct_by"):
        validate_rule_parameters(
            {
                "schema_version": 1,
                "rule_type": "distinct_threshold",
                "threshold": 10,
                "window_seconds": 60,
            }
        )


def test_unknown_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        validate_rule_parameters(
            {
                "schema_version": 1,
                "rule_type": "threshold",
                "threshold": 5,
                "window_seconds": 60,
                "python_expression": "__import__('os').system('id')",
            }
        )


def test_invalid_mitre_technique_is_rejected() -> None:
    with pytest.raises(ValidationError, match="technique_id"):
        validate_rule_parameters(
            {
                "schema_version": 1,
                "rule_type": "threshold",
                "threshold": 5,
                "window_seconds": 60,
                "mitre": {"technique_id": "BAD-ID"},
            }
        )


def test_legacy_empty_parameters_remain_valid() -> None:
    assert validate_rule_parameters({}) == {}


def test_api_schema_enforces_severity_and_expected_version() -> None:
    payload = DetectionRuleUpdate(
        severity=Severity.CRITICAL,
        expected_version=3,
        parameters={
            "schema_version": 1,
            "rule_type": "threshold",
            "threshold": 2,
            "window_seconds": 30,
        },
    )
    assert payload.severity == Severity.CRITICAL
    assert payload.expected_version == 3

    with pytest.raises(ValidationError):
        DetectionRuleUpdate(severity="SUPER_CRITICAL")
