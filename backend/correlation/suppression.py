"""In-memory cooldown suppression for repeated detections.

Suppression controls notification/incident emission only. CorrelationEngine still
feeds raw detections into sequence rules before suppression so higher-order attack
chains do not lose evidence.
"""

from __future__ import annotations

from datetime import datetime

from correlation.models import Detection


class DetectionSuppressor:
    """Suppress repeated detections for the same rule/entity during cooldown."""

    def __init__(self, default_cooldown_seconds: float = 0.0) -> None:
        if default_cooldown_seconds < 0:
            raise ValueError("default_cooldown_seconds must be >= 0")
        self._default_cooldown_seconds = default_cooldown_seconds
        self._last_emitted: dict[str, datetime] = {}
        self.suppressed_count = 0

    def should_emit(self, detection: Detection) -> bool:
        cooldown = float(
            detection.context.get("cooldown_seconds", self._default_cooldown_seconds) or 0
        )
        if cooldown <= 0:
            return True

        entity = detection.source_ip or detection.destination_ip or "global"
        key = f"{detection.rule_id}:{entity}"
        last = self._last_emitted.get(key)
        if last is not None:
            elapsed = (detection.timestamp - last).total_seconds()
            if elapsed < cooldown:
                self.suppressed_count += 1
                return False

        self._last_emitted[key] = detection.timestamp
        return True
