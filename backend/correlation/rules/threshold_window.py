"""Reusable threshold + sliding-window detection rule.

Supports both simple event-count thresholds and distinct-value aggregation such
as "N unique destination ports in T seconds". Domain-only; state is delegated
to CorrelationStateStore.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Hashable

from correlation.enums import Severity
from correlation.models import Detection
from correlation.rules.base import DetectionRule
from correlation.state import CorrelationStateStore
from events.models import NormalizedEvent

EventPredicate = Callable[[NormalizedEvent], bool]
GroupKey = Callable[[NormalizedEvent], str | None]
ValueKey = Callable[[NormalizedEvent], Hashable | None]


class ThresholdWindowRule(DetectionRule):
    """Trigger when a threshold is reached for one group inside a time window."""

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
        distinct_by: ValueKey | None = None,
        metric_name: str = "event_count",
        distinct_values_name: str | None = None,
        clear_on_trigger: bool = True,
        cooldown_seconds: float = 0.0,
    ) -> None:
        super().__init__(rule_id=rule_id, rule_name=rule_name)
        if threshold < 1:
            raise ValueError("threshold must be >= 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        if cooldown_seconds < 0:
            raise ValueError("cooldown_seconds must be >= 0")
        if not metric_name:
            raise ValueError("metric_name must not be empty")

        self._threshold = threshold
        self._window_seconds = window_seconds
        self._severity = severity
        self._predicate = predicate
        self._group_by = group_by
        self._title = title
        self._description = description
        self._mitre_technique = mitre_technique
        self._context = dict(context or {})
        self._distinct_by = distinct_by
        self._metric_name = metric_name
        self._distinct_values_name = distinct_values_name
        self._clear_on_trigger = clear_on_trigger
        self._cooldown_seconds = cooldown_seconds

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
            ttl_seconds=self._window_seconds * 2,
        )
        if not added:
            return []

        events = state_store.get_events(state_key, self._window_seconds)
        distinct_values: set[Hashable] | None = None
        if self._distinct_by is None:
            metric_value = len(events)
        else:
            distinct_values = {
                value
                for item in events
                if (value := self._distinct_by(item)) is not None
            }
            metric_value = len(distinct_values)

        if metric_value < self._threshold:
            return []

        context = {
            **self._context,
            "threshold": self._threshold,
            "window_seconds": self._window_seconds,
            "cooldown_seconds": self._cooldown_seconds,
            "group": group_value,
            "event_count": len(events),
            self._metric_name: metric_value,
        }
        if distinct_values is not None and self._distinct_values_name:
            try:
                context[self._distinct_values_name] = sorted(distinct_values)
            except TypeError:
                context[self._distinct_values_name] = list(distinct_values)
        if self._mitre_technique:
            context["mitre_technique"] = self._mitre_technique

        detection = Detection(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            severity=self._severity,
            title=self._title,
            description=self._description,
            timestamp=event.timestamp,
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            triggering_event_ids=[item.event_id for item in events],
            context=context,
        )
        if self._clear_on_trigger:
            state_store.clear_key(state_key)
        return [detection]
