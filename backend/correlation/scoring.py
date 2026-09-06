"""Deterministic scoring for detections.

AI may explain detections later, but risk/confidence here are derived only from
rule output and evidence so the detection truth boundary remains deterministic.
"""

from __future__ import annotations

from correlation.enums import Severity
from correlation.models import Detection

_SEVERITY_RISK = {
    Severity.LOW: 25,
    Severity.MEDIUM: 45,
    Severity.HIGH: 70,
    Severity.CRITICAL: 90,
}


def score_detection(detection: Detection) -> Detection:
    context = dict(detection.context)
    event_count = max(1, len(detection.triggering_event_ids))
    stage_count = len(context.get("stage_rule_ids", []))
    threshold = context.get("threshold")

    risk_score = _SEVERITY_RISK[detection.severity]
    risk_score += min(10, max(0, event_count - 1) * 2)
    risk_score += min(10, max(0, stage_count - 1) * 5)
    risk_score = min(100, risk_score)

    confidence_score = 55
    if threshold:
        observed = int(context.get("event_count", event_count))
        confidence_score += min(25, int((observed / max(1, int(threshold))) * 20))
    else:
        confidence_score += min(20, event_count * 4)
    if stage_count >= 2:
        confidence_score += min(20, stage_count * 5)
    if context.get("mitre_technique") or context.get("mitre_techniques"):
        confidence_score += 5
    confidence_score = min(100, confidence_score)

    context["risk_score"] = risk_score
    context["confidence_score"] = confidence_score
    context["scoring_model"] = "deterministic-v1"
    return detection.model_copy(update={"context": context})
