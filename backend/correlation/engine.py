"""CorrelationEngine — orchestrates event rules and higher-order detection sequences.

Primary detections are always fed into sequence correlation. Scoring and cooldown
suppression control outward emission only, preserving evidence for attack-chain
correlation while reducing duplicate incidents.
"""

from __future__ import annotations

import logging
from time import perf_counter
from typing import Sequence

from correlation.models import Detection
from correlation.rules.base import DetectionRule
from correlation.scoring import score_detection
from correlation.sequence import DetectionSequenceRule
from correlation.state import CorrelationStateStore
from correlation.suppression import DetectionSuppressor
from events.models import NormalizedEvent

logger = logging.getLogger(__name__)


class CorrelationEngine:
    """Orchestrates event rules, ordered sequences, scoring, and suppression."""

    def __init__(
        self,
        state_store: CorrelationStateStore,
        rules: Sequence[DetectionRule] | None = None,
        sequence_rules: Sequence[DetectionSequenceRule] | None = None,
        suppressor: DetectionSuppressor | None = None,
    ) -> None:
        self._state_store = state_store
        self._rules: list[DetectionRule] = list(rules) if rules is not None else []
        self._sequence_rules: list[DetectionSequenceRule] = (
            list(sequence_rules) if sequence_rules is not None else []
        )
        self._suppressor = suppressor or DetectionSuppressor()
        self._rules_evaluated = 0
        self._rules_matched = 0
        self._sequence_matches = 0
        self._errors = 0
        self._events_processed = 0
        self._processing_total_ms = 0.0
        self._processing_max_ms = 0.0

    def register_rule(self, rule: DetectionRule) -> None:
        self._rules.append(rule)

    def register_sequence_rule(self, rule: DetectionSequenceRule) -> None:
        self._sequence_rules.append(rule)

    @property
    def rules(self) -> list[DetectionRule]:
        return list(self._rules)

    @property
    def sequence_rules(self) -> list[DetectionSequenceRule]:
        return list(self._sequence_rules)

    def get_metrics(self) -> dict[str, int | float]:
        average_ms = (
            self._processing_total_ms / self._events_processed
            if self._events_processed
            else 0.0
        )
        return {
            "rules_evaluated": self._rules_evaluated,
            "rules_matched": self._rules_matched,
            "sequence_matches": self._sequence_matches,
            "suppressed_detections": self._suppressor.suppressed_count,
            "errors": self._errors,
            "events_processed": self._events_processed,
            "processing_avg_ms": round(average_ms, 3),
            "processing_max_ms": round(self._processing_max_ms, 3),
        }

    def process_event(self, event: NormalizedEvent) -> list[Detection]:
        started = perf_counter()
        try:
            raw_primary: list[Detection] = []
            for rule in self._rules:
                self._rules_evaluated += 1
                try:
                    matches = rule.evaluate(event, self._state_store)
                    if matches:
                        self._rules_matched += len(matches)
                        raw_primary.extend(matches)
                except Exception as exc:
                    self._errors += 1
                    logger.error(
                        "Error evaluating rule '%s' (%s) on event %s: %s",
                        rule.rule_id,
                        rule.rule_name,
                        event.event_id,
                        exc,
                    )

            scored_primary = [score_detection(item) for item in raw_primary]

            raw_derived: list[Detection] = []
            for detection in scored_primary:
                for sequence_rule in self._sequence_rules:
                    try:
                        matches = sequence_rule.evaluate(detection)
                        if matches:
                            self._sequence_matches += len(matches)
                            raw_derived.extend(matches)
                    except Exception as exc:
                        self._errors += 1
                        logger.error(
                            "Error evaluating sequence rule '%s' on detection %s: %s",
                            sequence_rule.rule_id,
                            detection.detection_id,
                            exc,
                        )

            scored_derived = [score_detection(item) for item in raw_derived]
            candidates = [*scored_primary, *scored_derived]
            return [item for item in candidates if self._suppressor.should_emit(item)]
        finally:
            elapsed_ms = (perf_counter() - started) * 1000.0
            self._events_processed += 1
            self._processing_total_ms += elapsed_ms
            self._processing_max_ms = max(self._processing_max_ms, elapsed_ms)
