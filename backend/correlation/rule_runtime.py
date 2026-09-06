"""Safe runtime compiler/manager for persisted detection rule configurations."""

from __future__ import annotations

from typing import Any, Hashable

from correlation.engine import CorrelationEngine
from correlation.enums import Severity
from correlation.rule_config import ThresholdRuleParameters
from correlation.rules.threshold_window import ThresholdWindowRule
from events.models import NormalizedEvent


def _condition_matches(event: NormalizedEvent, field: str, operator: str, expected: Any) -> bool:
    actual = getattr(event, field, None)
    if operator == "eq":
        return actual == expected
    if operator == "neq":
        return actual != expected
    if operator == "in":
        return actual in expected
    return False


def compile_persisted_rule(rule: dict[str, Any]) -> ThresholdWindowRule | None:
    """Compile one validated v1 DB rule without eval/exec/dynamic imports.

    Legacy metadata-only rules (empty parameters or missing schema_version) are
    deliberately ignored by the runtime compiler so existing deployments remain
    boot-compatible while new structured rules become executable.
    """
    parameters = rule.get("parameters") or {}
    if not parameters or parameters.get("schema_version") != 1:
        return None

    config = ThresholdRuleParameters.model_validate(parameters)

    def predicate(event: NormalizedEvent) -> bool:
        return all(
            _condition_matches(event, condition.field, condition.operator, condition.value)
            for condition in config.conditions
        )

    def group_by(event: NormalizedEvent) -> str | None:
        value = getattr(event, config.group_by, None)
        return str(value) if value is not None else None

    distinct_by = None
    metric_name = "event_count"
    distinct_values_name = None
    if config.rule_type == "distinct_threshold":
        distinct_field = config.distinct_by

        def distinct_by(event: NormalizedEvent) -> Hashable | None:  # type: ignore[no-redef]
            return getattr(event, distinct_field, None) if distinct_field else None

        metric_name = "distinct_values_count"
        distinct_values_name = "distinct_values"

    mitre_technique = config.mitre.technique_id if config.mitre else None
    context: dict[str, Any] = {
        "runtime_source": "persisted_rule",
        "config_schema_version": config.schema_version,
        "rule_type": config.rule_type,
        "rule_version": int(rule.get("version") or 1),
    }
    if config.mitre:
        context["mitre"] = config.mitre.model_dump(exclude_none=True)

    return ThresholdWindowRule(
        rule_id=str(rule["rule_id"]),
        rule_name=str(rule["rule_name"]),
        threshold=config.threshold,
        window_seconds=config.window_seconds,
        severity=Severity(rule["severity"]),
        predicate=predicate,
        group_by=group_by,
        title=str(rule["rule_name"]),
        description=str(rule.get("description") or rule["rule_name"]),
        mitre_technique=mitre_technique,
        context=context,
        distinct_by=distinct_by,
        metric_name=metric_name,
        distinct_values_name=distinct_values_name,
        cooldown_seconds=config.cooldown_seconds,
    )


class DetectionRuleRuntimeManager:
    """Apply persisted rule state to the live correlation engine."""

    def __init__(self, engine: CorrelationEngine) -> None:
        self._engine = engine

    def apply_rule(self, rule: dict[str, Any]) -> bool:
        rule_id = str(rule["rule_id"])
        if not rule.get("enabled", True):
            self._engine.remove_rule(rule_id)
            return True

        compiled = compile_persisted_rule(rule)
        if compiled is None:
            return False
        self._engine.upsert_rule(compiled)
        return True

    def apply_rules(self, rules: list[dict[str, Any]]) -> dict[str, int]:
        applied = 0
        skipped = 0
        for rule in rules:
            if self.apply_rule(rule):
                applied += 1
            else:
                skipped += 1
        return {"applied": applied, "skipped": skipped}
