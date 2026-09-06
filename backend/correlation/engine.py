"""
CorrelationEngine — orchestrates event rules and higher-order detection sequences.

NormalizedEvents are evaluated against registered DetectionRules first. Any
resulting detections are then passed through registered DetectionSequenceRules so
multi-stage attack chains become normal Detection objects and automatically flow
into the existing incident pipeline.
"""

from __future__ import annotations

import logging
from typing import Sequence

from correlation.models import Detection
from correlation.rules.base import DetectionRule
from correlation.sequence import DetectionSequenceRule
from correlation.state import CorrelationStateStore
from events.models import NormalizedEvent

logger = logging.getLogger(__name__)


class CorrelationEngine:
    """Orchestrates event detection rules and ordered detection sequences."""

    def __init__(
        self,
        state_store: CorrelationStateStore,
        rules: Sequence[DetectionRule] | None = None,
        sequence_rules: Sequence[DetectionSequenceRule] | None = None,
    ) -> None:
        self._state_store = state_store
        self._rules: list[DetectionRule] = list(rules) if rules is not None else []
        self._sequence_rules: list[DetectionSequenceRule] = (
            list(sequence_rules) if sequence_rules is not None else []
        )

    def register_rule(self, rule: DetectionRule) -> None:
        """Register a new event-level detection rule."""
        self._rules.append(rule)

    def register_sequence_rule(self, rule: DetectionSequenceRule) -> None:
        """Register a higher-order ordered detection sequence rule."""
        self._sequence_rules.append(rule)

    @property
    def rules(self) -> list[DetectionRule]:
        return list(self._rules)

    @property
    def sequence_rules(self) -> list[DetectionSequenceRule]:
        return list(self._sequence_rules)

    def process_event(self, event: NormalizedEvent) -> list[Detection]:
        """Evaluate an event and return both primary and derived chain detections."""
        primary_detections: list[Detection] = []
        for rule in self._rules:
            try:
                primary_detections.extend(rule.evaluate(event, self._state_store))
            except Exception as exc:
                logger.error(
                    "Error evaluating rule '%s' (%s) on event %s: %s",
                    rule.rule_id,
                    rule.rule_name,
                    event.event_id,
                    exc,
                )
                continue

        derived_detections: list[Detection] = []
        for detection in primary_detections:
            for sequence_rule in self._sequence_rules:
                try:
                    derived_detections.extend(sequence_rule.evaluate(detection))
                except Exception as exc:
                    logger.error(
                        "Error evaluating sequence rule '%s' on detection %s: %s",
                        sequence_rule.rule_id,
                        detection.detection_id,
                        exc,
                    )
                    continue

        return [*primary_detections, *derived_detections]
