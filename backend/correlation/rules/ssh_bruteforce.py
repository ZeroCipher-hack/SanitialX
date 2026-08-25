"""
SSHBruteForceDetectionRule — detects high-frequency TCP connections to SSH port 22.

Architecture Invariant #2:
TCP port 22 connections are network observations. They do NOT fabricate SSH login success/failure.
This rule monitors the frequency of connection attempts targeting port 22 and raises a
Detection when connection attempts exceed threshold N within window T.
"""

from __future__ import annotations

from correlation.enums import Severity
from correlation.models import Detection
from correlation.rules.base import DetectionRule
from correlation.state import CorrelationStateStore
from events.models import NormalizedEvent


class SSHBruteForceDetectionRule(DetectionRule):
    """Detects potential SSH brute-force or connection flood targeting port 22."""

    def __init__(
        self,
        rule_id: str = "RULE-SSH-BRUTEFORCE-01",
        rule_name: str = "SSH Brute-Force Detection",
        ssh_port: int = 22,
        attempt_threshold: int = 5,
        window_seconds: float = 60.0,
        severity: Severity = Severity.HIGH,
    ) -> None:
        super().__init__(rule_id=rule_id, rule_name=rule_name)
        self._ssh_port = ssh_port
        self._attempt_threshold = attempt_threshold
        self._window_seconds = window_seconds
        self._severity = severity

    def evaluate(
        self,
        event: NormalizedEvent,
        state_store: CorrelationStateStore,
    ) -> list[Detection]:
        if not event.source_ip or event.destination_port != self._ssh_port:
            return []

        state_key = f"ssh_attempts:{event.source_ip}"
        added = state_store.add_event(state_key, event, ttl_seconds=self._window_seconds * 2)
        if not added:
            return []

        window_events = state_store.get_events(state_key, window_seconds=self._window_seconds)

        if len(window_events) >= self._attempt_threshold:
            triggering_ids = [e.event_id for e in window_events]
            detection = Detection(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self._severity,
                title=f"Potential SSH Brute-Force from {event.source_ip}",
                description=(
                    f"Source IP {event.source_ip} made {len(window_events)} "
                    f"attempts to port {self._ssh_port} within {self._window_seconds}s."
                ),
                source_ip=event.source_ip,
                destination_ip=event.destination_ip,
                triggering_event_ids=triggering_ids,
                context={
                    "attempts_count": len(window_events),
                    "ssh_port": self._ssh_port,
                    "window_seconds": self._window_seconds,
                },
            )
            state_store.clear_key(state_key)
            return [detection]

        return []
