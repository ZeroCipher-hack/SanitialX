"""Correlate vulnerability exposure with historical SIEM events."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from correlation.enums import Severity
from db.repositories.event_repository import PostgresEventRepository
from db.repositories.incident_repository import PostgresIncidentRepository
from incidents.models import Incident
from incidents.service import IncidentService


_EXPLOIT_TOKENS = (
    "exploit", "rce", "remote code execution", "command injection", "shell",
    "payload", "webshell", "privilege escalation", "sql injection", "sqli",
    "directory traversal", "path traversal", "deserialization", "buffer overflow",
)


def _event_text(event) -> str:
    return " ".join(
        str(part or "")
        for part in (
            event.event_type,
            event.details,
            event.rule_id,
            event.mitre_technique,
            event.raw_payload,
        )
    ).lower()


def score_event_evidence(*, event, cve_id: str, product: str | None, known_exploited: bool) -> tuple[int, list[str]]:
    """Return deterministic correlation score and evidence reasons."""
    text = _event_text(event)
    score = 0
    reasons: list[str] = []

    if cve_id.lower() in text:
        score += 60
        reasons.append("event explicitly references CVE")
    if product and product.lower() in text:
        score += 20
        reasons.append("event references affected product")
    if any(token in text for token in _EXPLOIT_TOKENS):
        score += 20
        reasons.append("exploit-like activity keyword detected")
    if str(event.severity).upper() in {"HIGH", "CRITICAL"}:
        score += 15
        reasons.append("high-severity security event")
    if known_exploited:
        score += 10
        reasons.append("CVE is present in CISA KEV")

    return min(score, 100), reasons


class VulnerabilityEventCorrelator:
    def __init__(self, session) -> None:
        self._events = PostgresEventRepository(session)
        self._incidents = IncidentService(PostgresIncidentRepository(session))

    async def correlate_exposure(
        self,
        *,
        exposure,
        vulnerability,
        agent: dict[str, Any],
        lookback_days: int = 30,
        create_incident: bool = True,
    ) -> dict[str, Any]:
        since = datetime.now(timezone.utc) - timedelta(days=max(1, lookback_days))
        events = await self._events.list_asset_events(
            hostname=agent.get("hostname"),
            ip_address=agent.get("ip_address"),
            since=since,
        )

        product = (exposure.matched_software or {}).get("product")
        evidence = []
        for event in events:
            score, reasons = score_event_evidence(
                event=event,
                cve_id=vulnerability.cve_id,
                product=product,
                known_exploited=vulnerability.known_exploited,
            )
            if score < 40:
                continue
            evidence.append({
                "event_id": event.event_id,
                "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                "event_type": event.event_type,
                "severity": event.severity,
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip,
                "score": score,
                "reasons": reasons,
            })

        evidence.sort(key=lambda item: item["score"], reverse=True)
        best_score = evidence[0]["score"] if evidence else 0
        incident = None

        should_create = (
            create_incident
            and evidence
            and exposure.match_confidence >= 0.95
            and exposure.risk_score >= 70
            and best_score >= 70
        )
        if should_create:
            severity = Severity.CRITICAL if exposure.risk_score >= 90 or best_score >= 90 else Severity.HIGH
            incident = await self._incidents.create_incident(
                Incident(
                    title=f"Potential exploitation of {vulnerability.cve_id} on {agent.get('hostname') or exposure.agent_id}",
                    description=(
                        f"SanitialX correlated a confirmed vulnerability exposure with historical security events. "
                        f"Exposure risk={exposure.risk_score}, event evidence={best_score}."
                    ),
                    severity=severity,
                    source_ip=evidence[0].get("source_ip"),
                    destination_ip=agent.get("ip_address"),
                    triggering_detection_ids=[item["event_id"] for item in evidence[:10]],
                    context={
                        "source": "vulnerability_correlation",
                        "cve_id": vulnerability.cve_id,
                        "agent_id": exposure.agent_id,
                        "exposure_risk_score": exposure.risk_score,
                        "match_confidence": exposure.match_confidence,
                        "event_evidence_score": best_score,
                        "matched_software": exposure.matched_software,
                        "evidence": evidence[:20],
                    },
                )
            )

        return {
            "cve_id": vulnerability.cve_id,
            "agent_id": exposure.agent_id,
            "matched_events": len(evidence),
            "best_evidence_score": best_score,
            "incident_created": incident is not None,
            "incident_id": incident.incident_id if incident else None,
            "evidence": evidence[:20],
        }
