"""Validated configuration contract for persisted detection rules.

The database may contain legacy rules with an empty parameters object. New
structured configurations use schema_version=1 and are validated before write.
This module intentionally describes configuration only; it does not execute
untrusted expressions or dynamically import code.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class RuleCondition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field: Literal[
        "event_type",
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
        "protocol",
        "sensor_id",
    ]
    operator: Literal["eq", "neq", "in"] = "eq"
    value: str | int | list[str] | list[int]

    @model_validator(mode="after")
    def validate_operator_value(self) -> "RuleCondition":
        if self.operator == "in" and not isinstance(self.value, list):
            raise ValueError("operator 'in' requires a list value")
        if self.operator != "in" and isinstance(self.value, list):
            raise ValueError("eq/neq operators require a scalar value")
        return self


class MitreMapping(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tactic: str | None = Field(default=None, max_length=120)
    technique_id: str | None = Field(default=None, pattern=r"^T\d{4}(?:\.\d{3})?$")
    technique: str | None = Field(default=None, max_length=160)


class ThresholdRuleParameters(BaseModel):
    """Versioned safe subset for configurable threshold/window rules."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    rule_type: Literal["threshold", "distinct_threshold"]
    conditions: list[RuleCondition] = Field(default_factory=list, max_length=20)
    group_by: Literal["source_ip", "destination_ip", "sensor_id"] = "source_ip"
    threshold: int = Field(ge=1, le=100_000)
    window_seconds: float = Field(gt=0, le=86_400)
    cooldown_seconds: float = Field(default=0, ge=0, le=604_800)
    distinct_by: Literal["destination_port", "source_port", "destination_ip"] | None = None
    mitre: MitreMapping | None = None

    @model_validator(mode="after")
    def validate_distinct_contract(self) -> "ThresholdRuleParameters":
        if self.rule_type == "distinct_threshold" and self.distinct_by is None:
            raise ValueError("distinct_threshold requires distinct_by")
        if self.rule_type == "threshold" and self.distinct_by is not None:
            raise ValueError("threshold rules must not define distinct_by")
        return self


def validate_rule_parameters(parameters: dict[str, Any]) -> dict[str, Any]:
    """Return normalized parameters or raise Pydantic validation errors.

    Empty parameters remain valid for legacy built-in rules. Once a structured
    configuration is supplied it must conform to the versioned v1 contract.
    """
    if not parameters:
        return {}
    return ThresholdRuleParameters.model_validate(parameters).model_dump(exclude_none=True)
