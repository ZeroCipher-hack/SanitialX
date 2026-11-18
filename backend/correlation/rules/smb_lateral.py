"""SMB lateral-movement detection built on the reusable threshold-window engine.

TCP port 445 observations do not prove a successful remote-service login, so
this rule reports repeated SMB connection attempts from one source.
"""

from __future__ import annotations

from correlation.enums import Severity
from correlation.rules.threshold_window import ThresholdWindowRule


class SMBLateralMovementDetectionRule(ThresholdWindowRule):
    """Detect repeated connection attempts targeting SMB port 445."""

    def __init__(
        self,
        rule_id: str = "RULE-SMB-LATERAL-01",
        rule_name: str = "SMB Lateral Movement Detection",
        smb_port: int = 445,
        attempt_threshold: int = 10,
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
            and event.destination_port == smb_port,
            group_by=lambda event: event.source_ip,
            title="Potential SMB Lateral Movement Activity",
            description=(
                "Repeated TCP connection attempts to the configured SMB port "
                "exceeded the detection threshold."
            ),
            mitre_technique="T1021.002",
            context={"smb_port": smb_port, "detection_basis": "tcp_connection_frequency"},
            metric_name="attempts_count",
            cooldown_seconds=cooldown_seconds,
        )
