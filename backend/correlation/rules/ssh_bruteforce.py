"""SSH connection-flood detection built on the reusable threshold-window engine.

TCP port 22 observations do not prove authentication failure. This rule therefore
reports repeated SSH connection attempts, while preserving the historical class
name/API used by the worker and tests.
"""

from __future__ import annotations

from correlation.enums import Severity
from correlation.rules.threshold_window import ThresholdWindowRule


class SSHBruteForceDetectionRule(ThresholdWindowRule):
    """Detect repeated connection attempts targeting SSH port 22."""

    def __init__(
        self,
        rule_id: str = "RULE-SSH-BRUTEFORCE-01",
        rule_name: str = "SSH Brute-Force Detection",
        ssh_port: int = 22,
        attempt_threshold: int = 5,
        window_seconds: float = 60.0,
        severity: Severity = Severity.HIGH,
        cooldown_seconds: float = 120.0,
    ) -> None:
        super().__init__(
            rule_id=rule_id,
            rule_name=rule_name,
            threshold=attempt_threshold,
            window_seconds=window_seconds,
            severity=severity,
            predicate=lambda event: bool(event.source_ip)
            and event.destination_port == ssh_port,
            group_by=lambda event: event.source_ip,
            title="Potential SSH Brute-Force Activity",
            description=(
                "Repeated TCP connection attempts to the configured SSH port "
                "exceeded the detection threshold."
            ),
            mitre_technique="T1110",
            context={"ssh_port": ssh_port, "detection_basis": "tcp_connection_frequency"},
            metric_name="attempts_count",
            cooldown_seconds=cooldown_seconds,
        )
