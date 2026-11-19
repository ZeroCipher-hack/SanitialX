"""Database-service connection-flood detection built on the threshold-window engine.

TCP observations on database ports do not prove authentication failure, so this
rule reports repeated connection attempts to common database services.
"""

from __future__ import annotations

from correlation.enums import Severity
from correlation.rules.threshold_window import ThresholdWindowRule

DEFAULT_DATABASE_PORTS = frozenset({1433, 3306, 5432})


class DatabaseBruteForceDetectionRule(ThresholdWindowRule):
    """Detect repeated connection attempts targeting database ports."""

    def __init__(
        self,
        rule_id: str = "RULE-DB-BRUTEFORCE-01",
        rule_name: str = "Database Brute-Force Detection",
        database_ports: frozenset[int] | set[int] = DEFAULT_DATABASE_PORTS,
        attempt_threshold: int = 8,
        window_seconds: float = 60.0,
        severity: Severity = Severity.HIGH,
        cooldown_seconds: float = 120.0,
    ) -> None:
        ports = frozenset(database_ports)
        super().__init__(
            rule_id=rule_id,
            rule_name=rule_name,
            threshold=attempt_threshold,
            window_seconds=window_seconds,
            severity=severity,
            predicate=lambda event: bool(event.source_ip)
            and event.destination_port in ports,
            group_by=lambda event: event.source_ip,
            title="Potential Database Brute-Force Activity",
            description=(
                "Repeated TCP connection attempts to database service ports "
                "exceeded the detection threshold."
            ),
            mitre_technique="T1110",
            context={
                "database_ports": sorted(ports),
                "detection_basis": "tcp_connection_frequency",
            },
            metric_name="attempts_count",
            cooldown_seconds=cooldown_seconds,
        )
