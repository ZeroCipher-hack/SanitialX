"""
PortScanDetectionRule — detects port scanning activity.

Triggers when a single source IP connects to distinct destination ports
exceeding threshold N within time window T.
Thresholds are configurable constructor parameters — zero magic numbers.
"""

from __future__ import annotations

from correlation.enums import Severity
from correlation.models import Detection
from correlation.rules.base import DetectionRule
from correlation.state import CorrelationStateStore
from events.enums import EventType
from events.models import NormalizedEvent


class PortScanDetectionRule(DetectionRule):
    """Detects potential port scan when source IP touches N distinct ports in T seconds."""

    def __init__(
        self,
        rule_id: str = "RULE-PORT-SCAN-01",
        rule_name: str = "Port Scan Detection",
        distinct_ports_threshold: int = 10,
        window_seconds: float = 60.0,
        severity: Severity = Severity.HIGH,
    ) -> None:
        super().__init__(rule_id=rule_id, rule_name=rule_name)
        self._distinct_ports_threshold = distinct_ports_threshold
        self._window_seconds = window_seconds
        self._severity = severity

    def evaluate(
        self,
        event: NormalizedEvent,
        state_store: CorrelationStateStore,
    ) -> list[Detection]:
        # Only analyze events with source_ip and destination_port
        if not event.source_ip or event.destination_port is None:
            return []

        # Deduplicating add
        state_key = f"port_scan:{event.source_ip}"
        added = state_store.add_event(state_key, event, ttl_seconds=self._window_seconds * 2)
        if not added:
            # Event was duplicate, do not double-count
            return []

        # Retrieve window events
        window_events = state_store.get_events(state_key, window_seconds=self._window_seconds)

        distinct_ports = {
            e.destination_port for e in window_events if e.destination_port is not None
        }

        if len(distinct_ports) >= self._distinct_ports_threshold:
            triggering_ids = [e.event_id for e in window_events]
            detection = Detection(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self._severity,
                title=f"Port Scan Detected from {event.source_ip}",
                description=(
                    f"Source IP {event.source_ip} touched {len(distinct_ports)} "
                    f"distinct ports within {self._window_seconds}s window."
                ),
                source_ip=event.source_ip,
                destination_ip=event.destination_ip,
                triggering_event_ids=triggering_ids,
                context={
                    "distinct_ports_count": len(distinct_ports),
                    "distinct_ports": sorted(list(distinct_ports)),
                    "window_seconds": self._window_seconds,
                },
            )
            # Clear state after detection to prevent immediate redundant alerts
            state_store.clear_key(state_key)
            return [detection]

        return []
