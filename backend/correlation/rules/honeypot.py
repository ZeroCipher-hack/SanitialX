"""
HoneypotDetectionRule — detects traffic targeting designated honeypot ports.

Triggers immediately when any packet targets a designated honeypot port.
Honeypot ports are fully configurable via constructor parameters.
"""

from __future__ import annotations

from typing import Set

from correlation.enums import Severity
from correlation.models import Detection
from correlation.rules.base import DetectionRule
from correlation.state import CorrelationStateStore
from events.models import NormalizedEvent


class HoneypotDetectionRule(DetectionRule):
    """Detects any event touching a designated honeypot port."""

    def __init__(
        self,
        rule_id: str = "RULE-HONEYPOT-01",
        rule_name: str = "Honeypot Port Activity",
        honeypot_ports: set[int] | None = None,
        severity: Severity = Severity.CRITICAL,
    ) -> None:
        super().__init__(rule_id=rule_id, rule_name=rule_name)
        self._honeypot_ports: set[int] = honeypot_ports if honeypot_ports is not None else {31337, 2323, 1025}
        self._severity = severity

    def evaluate(
        self,
        event: NormalizedEvent,
        state_store: CorrelationStateStore,
    ) -> list[Detection]:
        if event.destination_port is None or event.destination_port not in self._honeypot_ports:
            return []

        state_key = f"honeypot:{event.destination_port}:{event.source_ip}"
        added = state_store.add_event(state_key, event, ttl_seconds=300)
        if not added:
            return []

        return [
            Detection(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self._severity,
                title=f"Honeypot Triggered on Port {event.destination_port}",
                description=(
                    f"Traffic from source IP {event.source_ip or 'unknown'} "
                    f"accessed honeypot port {event.destination_port}."
                ),
                source_ip=event.source_ip,
                destination_ip=event.destination_ip,
                triggering_event_ids=[event.event_id],
                context={
                    "honeypot_port": event.destination_port,
                    "protocol": event.protocol,
                },
            )
        ]
