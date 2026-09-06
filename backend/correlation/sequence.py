"""Multi-stage attack-chain correlation for detections.

Correlates ordered detections sharing an entity (normally source IP) inside a
bounded time window. The component is deliberately separate from event rules so
single-event/threshold detections remain reusable and testable.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from correlation.enums import Severity
from correlation.models import Detection


@dataclass(frozen=True)
class SequenceStage:
    rule_id: str
    name: str
    mitre_technique: str | None = None


class DetectionSequenceRule:
    """Trigger after ordered detection stages occur for the same entity."""

    def __init__(
        self,
        *,
        rule_id: str,
        rule_name: str,
        stages: list[SequenceStage],
        window_seconds: float,
        severity: Severity = Severity.CRITICAL,
        title: str = "Multi-stage attack chain detected",
        cooldown_seconds: float = 300.0,
    ) -> None:
        if len(stages) < 2:
            raise ValueError("sequence requires at least two stages")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        if cooldown_seconds < 0:
            raise ValueError("cooldown_seconds must be >= 0")
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.stages = tuple(stages)
        self.window_seconds = window_seconds
        self.severity = severity
        self.title = title
        self.cooldown_seconds = cooldown_seconds
        self._progress: dict[str, list[Detection]] = {}

    def evaluate(self, detection: Detection) -> list[Detection]:
        entity = detection.source_ip
        if not entity:
            return []

        progress = self._progress.get(entity, [])
        cutoff = detection.timestamp - timedelta(seconds=self.window_seconds)
        progress = [item for item in progress if item.timestamp >= cutoff]

        expected_index = len(progress)
        if expected_index >= len(self.stages):
            progress = []
            expected_index = 0

        expected = self.stages[expected_index]
        if detection.rule_id == expected.rule_id:
            progress.append(detection)
        elif detection.rule_id == self.stages[0].rule_id:
            progress = [detection]
        else:
            self._progress[entity] = progress
            return []

        if len(progress) < len(self.stages):
            self._progress[entity] = progress
            return []

        self._progress.pop(entity, None)
        event_ids = list(dict.fromkeys(
            event_id
            for item in progress
            for event_id in item.triggering_event_ids
        ))
        techniques = [
            stage.mitre_technique for stage in self.stages if stage.mitre_technique
        ]
        return [Detection(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self.severity,
            title=self.title,
            description=(
                f"Ordered attack stages completed for {entity} within "
                f"{self.window_seconds}s: " + " -> ".join(stage.name for stage in self.stages)
            ),
            timestamp=detection.timestamp,
            source_ip=entity,
            destination_ip=detection.destination_ip,
            triggering_event_ids=event_ids,
            context={
                "correlation_type": "ordered_sequence",
                "window_seconds": self.window_seconds,
                "cooldown_seconds": self.cooldown_seconds,
                "stages": [stage.name for stage in self.stages],
                "stage_rule_ids": [stage.rule_id for stage in self.stages],
                "mitre_techniques": techniques,
                "source_detection_ids": [item.detection_id for item in progress],
            },
        )]
