"""
CorrelationEngine — orchestrates detection rules against incoming events.

Evaluates NormalizedEvents against a registered collection of DetectionRules
using the CorrelationStateStore.
"""

from __future__ import annotations

import logging
from typing import Sequence

from correlation.models import Detection
from correlation.rules.base import DetectionRule
from correlation.state import CorrelationStateStore
from events.models import NormalizedEvent

logger = logging.getLogger(__name__)


class CorrelationEngine:
    """Orchestrates detection rules evaluation."""

    def __init__(
        self,
        state_store: CorrelationStateStore,
        rules: Sequence[DetectionRule] | None = None,
    ) -> None:
        self._state_store = state_store
        self._rules: list[DetectionRule] = list(rules) if rules is not None else []

    def register_rule(self, rule: DetectionRule) -> None:
        """Register a new detection rule."""
        self._rules.append(rule)

    @property
    def rules(self) -> list[DetectionRule]:
        return list(self._rules)

    def process_event(self, event: NormalizedEvent) -> list[Detection]:
        """Evaluate event against all registered rules and return triggered Detections."""
        detections: list[Detection] = []
        for rule in self._rules:
            try:
                rule_detections = rule.evaluate(event, self._state_store)
                detections.extend(rule_detections)
            except Exception as exc:
                logger.error(
                    "Error evaluating rule '%s' (%s) on event %s: %s",
                    rule.rule_id,
                    rule.rule_name,
                    event.event_id,
                    exc,
                )
                # Failure in one rule must not prevent other rules from running
                continue
        return detections
