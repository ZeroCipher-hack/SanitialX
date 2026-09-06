from __future__ import annotations

from datetime import datetime, timedelta, timezone

from correlation.enums import Severity
from correlation.models import Detection
from correlation.sequence import DetectionSequenceRule, SequenceStage


def _d(rule_id: str, *, src: str = "1.2.3.4", seconds: int = 0, event_id: str = "e") -> Detection:
    return Detection(
        rule_id=rule_id,
        rule_name=rule_id,
        severity=Severity.HIGH,
        title=rule_id,
        description=rule_id,
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds),
        source_ip=src,
        triggering_event_ids=[event_id],
    )


def _rule() -> DetectionSequenceRule:
    return DetectionSequenceRule(
        rule_id="RULE-ATTACK-CHAIN-01",
        rule_name="Recon to SSH Attack Chain",
        stages=[
            SequenceStage("RULE-PORT-SCAN-01", "Reconnaissance", "T1046"),
            SequenceStage("RULE-SSH-BRUTEFORCE-01", "Credential Access", "T1110"),
        ],
        window_seconds=300,
    )


def test_sequence_triggers_in_order_for_same_source() -> None:
    rule = _rule()
    assert rule.evaluate(_d("RULE-PORT-SCAN-01", seconds=0, event_id="scan")) == []
    result = rule.evaluate(_d("RULE-SSH-BRUTEFORCE-01", seconds=30, event_id="ssh"))
    assert len(result) == 1
    detection = result[0]
    assert detection.severity == Severity.CRITICAL
    assert detection.triggering_event_ids == ["scan", "ssh"]
    assert detection.context["mitre_techniques"] == ["T1046", "T1110"]


def test_sequence_does_not_mix_sources() -> None:
    rule = _rule()
    rule.evaluate(_d("RULE-PORT-SCAN-01", src="1.1.1.1", event_id="scan"))
    assert rule.evaluate(_d("RULE-SSH-BRUTEFORCE-01", src="2.2.2.2", seconds=10, event_id="ssh")) == []


def test_sequence_expires_outside_window() -> None:
    rule = _rule()
    rule.evaluate(_d("RULE-PORT-SCAN-01", seconds=0, event_id="scan"))
    assert rule.evaluate(_d("RULE-SSH-BRUTEFORCE-01", seconds=301, event_id="ssh")) == []


def test_sequence_requires_order() -> None:
    rule = _rule()
    assert rule.evaluate(_d("RULE-SSH-BRUTEFORCE-01", seconds=0, event_id="ssh")) == []
    assert rule.evaluate(_d("RULE-PORT-SCAN-01", seconds=10, event_id="scan")) == []
