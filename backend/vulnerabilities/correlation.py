"""Correlate vulnerability exposure with historical or live SIEM events."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from correlation.enums import Severity
from db.repositories.event_repository import PostgresEventRepository
from db.repositories.incident_repository import PostgresIncidentRepository
from incidents.enums import IncidentStatus
from incidents.models import Incident
from incidents.service import IncidentService


_EXPLOIT_TOKENS = (
    "exploit", "rce", "remote code execution", "command injection", "shell",
    "payload", "webshell", "privilege escalation", "sql injection", "sqli",
    "directory traversal", "path traversal", "deserialization", "buffer overflow",
)


def _event_text(event) -> str:
    metadata = getattr(event, "metadata", None)
    raw_payload = getattr(event, "raw_payload", None)
    return " ".join(
        str(part or "")
        for part in (
            getattr(event, "event_type", None),
            getattr(event, "details", None),
            getattr(event, "rule_id", None),
            getattr(event, "mitre_technique", None),
            raw_payload,
            metadata,
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
    if str(getattr(event, "severity", "")).upper() in {"HIGH", "CRITICAL"}:
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

    async def _find_existing_open_incident(self, *, cve_id: str, agent_id: str):
        incidents = await self._incidents.list_incidents(limit=500, offset=0)
        for incident in incidents:
            context = incident.context or {}
            if (
                context.get("source") == "vulnerability_correlation"
                and str(context.get("cve_id", "")).upper() == cve_id.upper()
                and context.get("agent_id") == agent_id
                and incident.status in {IncidentStatus.OPEN, IncidentStatus.INVESTIGATING}
            ):
                return incident
        return None

    async def _create_incident_if_needed(
        self,
        *,
        exposure,
        vulnerability,
        agent: dict[str, Any],
        evidence: list[dict[str, Any]],
        best_score: int,
        create_incident: bool,
    ):
        should_create = (
            create_incident
            and evidence
            and exposure.match_confidence >= 0.95
            and exposure.risk_score >= 70
            and best_score >= 70
        )
        if not should_create:
            return None, False

        existing = await self._find_existing_open_incident(
            cve_id=vulnerability.cve_id,
            agent_id=exposure.agent_id,
        )
        if existing is not None:
            return existing, True

        severity = Severity.CRITICAL if exposure.risk_score >= 90 or best_score >= 90 else Severity.HIGH
        incident = await self._incidents.create_incident(
            Incident(
                title=f"Potential exploitation of {vulnerability.cve_id} on {agent.get('hostname') or exposure.agent_id}",
                description=(
                    f"SanitialX correlated a confirmed vulnerability exposure with security events. "
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
        return incident, False

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
        incident, deduplicated = await self._create_incident_if_needed(
            exposure=exposure,
            vulnerability=vulnerability,
            agent=agent,
            evidence=evidence,
            best_score=best_score,
            create_incident=create_incident,
        )

        return {
            "cve_id": vulnerability.cve_id,
            "agent_id": exposure.agent_id,
            "matched_events": len(evidence),
            "best_evidence_score": best_score,
            "incident_created": incident is not None and not deduplicated,
            "incident_deduplicated": deduplicated,
            "incident_id": incident.incident_id if incident else None,
            "evidence": evidence[:20],
        }

    async def correlate_live_event(
        self,
        *,
        event,
        exposure,
        vulnerability,
        agent: dict[str, Any],
        create_incident: bool = True,
    ) -> dict[str, Any]:
        product = (exposure.matched_software or {}).get("product")
        score, reasons = score_event_evidence(
            event=event,
            cve_id=vulnerability.cve_id,
            product=product,
            known_exploited=vulnerability.known_exploited,
        )
        evidence = []
        if score >= 40:
            evidence.append({
                "event_id": event.event_id,
                "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                "event_type": event.event_type,
                "severity": str(getattr(event, "severity", "INFO")),
                "source_ip": getattr(event, "source_ip", None),
                "destination_ip": getattr(event, "destination_ip", None),
                "score": score,
                "reasons": reasons,
            })

        incident, deduplicated = await self._create_incident_if_needed(
            exposure=exposure,
            vulnerability=vulnerability,
            agent=agent,
            evidence=evidence,
            best_score=score,
            create_incident=create_incident,
        )
        return {
            "cve_id": vulnerability.cve_id,
            "agent_id": exposure.agent_id,
            "best_evidence_score": score,
            "incident_created": incident is not None and not deduplicated,
            "incident_deduplicated": deduplicated,
            "incident_id": incident.incident_id if incident else None,
        }
