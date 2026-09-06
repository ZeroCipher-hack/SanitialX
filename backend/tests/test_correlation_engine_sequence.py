from __future__ import annotations

from datetime import datetime, timezone

from correlation.engine import CorrelationEngine
from correlation.enums import Severity
from correlation.rules.port_scan import PortScanDetectionRule
from correlation.rules.ssh_bruteforce import SSHBruteForceDetectionRule
from correlation.sequence import DetectionSequenceRule, SequenceStage
from correlation.state import InMemoryCorrelationStateStore
from events.models import NormalizedEvent


def _event(event_id: str, dport: int) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        event_type="TCP",
        timestamp=datetime.now(timezone.utc),
        source_ip="9.9.9.9",
        destination_ip="10.0.0.10",
        destination_port=dport,
        protocol="TCP",
        sensor_id="test-sensor",
    )


def test_engine_emits_attack_chain_detection() -> None:
    engine = CorrelationEngine(
        InMemoryCorrelationStateStore(),
        rules=[
            PortScanDetectionRule(distinct_ports_threshold=2, window_seconds=60),
            SSHBruteForceDetectionRule(attempt_threshold=2, window_seconds=60),
        ],
        sequence_rules=[
            DetectionSequenceRule(
                rule_id="RULE-ATTACK-CHAIN-01",
                rule_name="Recon to SSH Attack Chain",
                stages=[
                    SequenceStage("RULE-PORT-SCAN-01", "Reconnaissance", "T1046"),
                    SequenceStage("RULE-SSH-BRUTEFORCE-01", "Credential Access", "T1110"),
                ],
                window_seconds=300,
                severity=Severity.CRITICAL,
            )
        ],
    )

    assert engine.process_event(_event("scan-1", 80)) == []
    scan_result = engine.process_event(_event("scan-2", 443))
    assert any(item.rule_id == "RULE-PORT-SCAN-01" for item in scan_result)

    assert engine.process_event(_event("ssh-1", 22)) == []
    ssh_result = engine.process_event(_event("ssh-2", 22))

    rule_ids = [item.rule_id for item in ssh_result]
    assert "RULE-SSH-BRUTEFORCE-01" in rule_ids
    assert "RULE-ATTACK-CHAIN-01" in rule_ids
    chain = next(item for item in ssh_result if item.rule_id == "RULE-ATTACK-CHAIN-01")
    assert chain.severity == Severity.CRITICAL
    assert chain.context["mitre_techniques"] == ["T1046", "T1110"]
