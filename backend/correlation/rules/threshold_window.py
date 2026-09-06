"""Reusable threshold + sliding-window detection rule.

This rule turns repeated matching events into a single higher-confidence detection.
It is intentionally domain-only and reuses the existing CorrelationStateStore for
window tracking and event-id deduplication.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from correlation.enums import Severity
from correlation.models import Detection
from correlation.rules.base import DetectionRule
from correlation.state import CorrelationStateStore
from events.models import NormalizedEvent

EventPredicate = Callable[[NormalizedEvent], bool]
GroupKey = Callable[[NormalizedEvent], str | None]


class ThresholdWindowRule(DetectionRule):
    """Trigger when N matching events occur for the same group inside a window."""

    def __init__(
        self,
        *,
        rule_id: str,
        rule_name: str,
        threshold: int,
        window_seconds: float,
        severity: Severity,
        predicate: EventPredicate,
        group_by: GroupKey,
        title: str,
        description: str,
        mitre_technique: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(rule_id=rule_id, rule_name=rule_name)
        if threshold < 1:
            raise ValueError("threshold must be >= 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")

        self._threshold = threshold
        self._window_seconds = window_seconds
        self._severity = severity
        self._predicate = predicate
        self._group_by = group_by
        self._title = title
        self._description = description
        self._mitre_technique = mitre_technique
        self._context = dict(context or {})

    def evaluate(
        self,
        event: NormalizedEvent,
        state_store: CorrelationStateStore,
    ) -> list[Detection]:
        if not self._predicate(event):
            return []

        group_value = self._group_by(event)
        if not group_value:
            return []

        state_key = f"threshold:{self.rule_id}:{group_value}"
        added = state_store.add_event(
            state_key,
            event,
            ttl_seconds=self._window_seconds,
        )
        if not added:
            return []

        events = state_store.get_events(state_key, self._window_seconds)
        if len(events) < self._threshold:
            return []

        triggering_events = events[-self._threshold :]
        context = {
            **self._context,
            "threshold": self._threshold,
            "window_seconds": self._window_seconds,
            "group": group_value,
            "event_count": len(events),
        }
        if self._mitre_technique:
            context["mitre_technique"] = self._mitre_technique

        return [
            Detection(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self._severity,
                title=self._title,
                description=self._description,
                timestamp=event.timestamp,
                source_ip=event.source_ip,
                destination_ip=event.destination_ip,
                triggering_event_ids=[item.event_id for item in triggering_events],
                context=context,
            )
        ]
