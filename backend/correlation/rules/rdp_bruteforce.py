"""RDP connection-flood detection built on the reusable threshold-window engine.

Like the SSH rule, TCP port 3389 observations do not prove authentication
failure, so this rule reports repeated RDP connection attempts.
"""

from __future__ import annotations

from correlation.enums import Severity
from correlation.rules.threshold_window import ThresholdWindowRule


class RDPBruteForceDetectionRule(ThresholdWindowRule):
    """Detect repeated connection attempts targeting RDP port 3389."""

    def __init__(
        self,
        rule_id: str = "RULE-RDP-BRUTEFORCE-01",
        rule_name: str = "RDP Brute-Force Detection",
        rdp_port: int = 3389,
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
            and event.destination_port == rdp_port,
            group_by=lambda event: event.source_ip,
            title="Potential RDP Brute-Force Activity",
            description=(
                "Repeated TCP connection attempts to the configured RDP port "
                "exceeded the detection threshold."
            ),
            mitre_technique="T1110",
            context={"rdp_port": rdp_port, "detection_basis": "tcp_connection_frequency"},
            metric_name="attempts_count",
            cooldown_seconds=cooldown_seconds,
        )
