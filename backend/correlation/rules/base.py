"""
DetectionRule abstraction for SentinelX.

Defines the single canonical interface for stateful correlation and detection rules.
Rules evaluate NormalizedEvents and produce zero or more Detection objects.
"""

from __future__ import annotations

import abc

from correlation.models import Detection
from correlation.state import CorrelationStateStore
from events.models import NormalizedEvent


class DetectionRule(abc.ABC):
    """Abstract base class for all detection rules in SentinelX.

    Invariants:
    - Exactly ONE DetectionRule interface in the codebase.
    - Rule thresholds must be parameters passed to __init__, never magic numbers.
    - Rules must deduplicate processing by event_id.
    - Domain code — zero infrastructure imports allowed.
    """

    def __init__(self, rule_id: str, rule_name: str) -> None:
        self._rule_id = rule_id
        self._rule_name = rule_name

    @property
    def rule_id(self) -> str:
        return self._rule_id

    @property
    def rule_name(self) -> str:
        return self._rule_name

    @abc.abstractmethod
    def evaluate(
        self,
        event: NormalizedEvent,
        state_store: CorrelationStateStore,
    ) -> list[Detection]:
        """Evaluate a NormalizedEvent against correlation state.

        Returns a list of Detection objects if the rule condition is triggered,
        or an empty list if no detection occurred.
        """
