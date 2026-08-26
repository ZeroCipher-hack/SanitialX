"""
Automated Incident Investigation Reports API Router for SanitialX.
"""

from __future__ import annotations

from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Query, status

from api.deps import get_current_user, get_incident_repository
from core.security import TokenPayload
from db.repositories.incident_repository import PostgresIncidentRepository

router = APIRouter(prefix="/reports", tags=["Investigation Reports"])


@router.get("")
async def list_reports(
    repo: Annotated[PostgresIncidentRepository, Depends(get_incident_repository)],
    _user: Annotated[TokenPayload, Depends(get_current_user)],
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    """List investigation reports derived from correlated security incidents."""
    incidents = await repo.list_all(limit=limit, offset=offset)
    reports = []
    for inc in incidents:
        context = inc.context or {}
        reports.append({
            "report_id": f"REP-{inc.incident_id}",
            "incident_id": inc.incident_id,
            "title": inc.title,
            "severity": inc.severity.value,
            "status": inc.status.value,
            "created_at": inc.created_at.isoformat(),
            "updated_at": inc.updated_at.isoformat(),
            "executive_summary": context.get("executive_summary", "No AI executive summary generated yet."),
            "overall_risk_score": context.get("overall_risk_score", 75),
            "observed_techniques_count": len(context.get("observed_techniques", [])),
            "affected_assets": context.get("affected_assets", []),
        })
    return reports


@router.get("/{incident_id}")
async def get_report_detail(
    incident_id: str,
    repo: Annotated[PostgresIncidentRepository, Depends(get_incident_repository)],
    _user: Annotated[TokenPayload, Depends(get_current_user)],
):
    """Get comprehensive automated investigation report for an incident."""
    inc = await repo.get_by_id(incident_id)
    if inc is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report for incident '{incident_id}' not found.",
        )

    context = inc.context or {}
    return {
        "report_id": f"REP-{inc.incident_id}",
        "incident_id": inc.incident_id,
        "title": inc.title,
        "severity": inc.severity.value,
        "status": inc.status.value,
        "created_at": inc.created_at.isoformat(),
        "updated_at": inc.updated_at.isoformat(),
        "source_ip": inc.source_ip,
        "destination_ip": inc.destination_ip,
        "triggering_detection_ids": inc.triggering_detection_ids,
        "executive_summary": context.get("executive_summary", f"AI Investigation for {inc.title}"),
        "initial_access_vector": context.get("initial_access_vector", "Brute force / Credential Reuse"),
        "affected_assets": context.get("affected_assets", [inc.destination_ip or "Target Host"]),
        "observed_techniques": context.get("observed_techniques", ["T1110", "T1078", "T1059"]),
        "honeypot_engagement": context.get("honeypot_engagement", "Attacker engaged with deception traps."),
        "simulated_data_loss": context.get("simulated_data_loss", "Customer DB Records"),
        "overall_risk_score": context.get("overall_risk_score", 85),
        "recommended_actions": context.get("recommended_actions", [
            "1. Block malicious source IP on firewall.",
            "2. Rotate compromised user credentials.",
            "3. Isolate affected endpoint.",
        ]),
        "graph_nodes": context.get("graph_nodes", []),
        "graph_edges": context.get("graph_edges", []),
    }
