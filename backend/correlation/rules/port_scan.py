"""Port-scan detection built on the reusable threshold-window engine."""

from __future__ import annotations

from correlation.enums import Severity
from correlation.rules.threshold_window import ThresholdWindowRule


class PortScanDetectionRule(ThresholdWindowRule):
    """Detect a source touching N distinct destination ports in T seconds."""

    def __init__(
        self,
        rule_id: str = "RULE-PORT-SCAN-01",
        rule_name: str = "Port Scan Detection",
        distinct_ports_threshold: int = 10,
        window_seconds: float = 60.0,
        severity: Severity = Severity.HIGH,
        cooldown_seconds: float = 180.0,
    ) -> None:
        super().__init__(
            rule_id=rule_id,
            rule_name=rule_name,
            threshold=distinct_ports_threshold,
            window_seconds=window_seconds,
            severity=severity,
            predicate=lambda event: bool(event.source_ip)
            and event.destination_port is not None,
            group_by=lambda event: event.source_ip,
            distinct_by=lambda event: event.destination_port,
            metric_name="distinct_ports_count",
            distinct_values_name="distinct_ports",
            title="Port Scan Detected",
            description=(
                "A single source touched multiple distinct destination ports "
                "inside the configured sliding window."
            ),
            context={"detection_basis": "distinct_destination_ports"},
            cooldown_seconds=cooldown_seconds,
        )
