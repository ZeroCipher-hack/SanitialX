"""Automated Incident Investigation Reports API Router for SanitialX."""

from __future__ import annotations

import asyncio
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from api.deps import get_current_user, get_incident_repository
from core.config import get_settings
from core.security import TokenPayload
from db.repositories.incident_repository import PostgresIncidentRepository
from services.ai_analysis import AIIncidentAnalysis, analyze_incident, fallback_analysis

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/reports", tags=["Investigation Reports"])


def _report_fields(inc, analysis: AIIncidentAnalysis) -> dict:
    """Merge database incident metadata with structured AI analysis."""
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
        "executive_summary": analysis.executive_summary,
        "threat_classification": analysis.threat_classification,
        "confidence_score": analysis.confidence_score,
        "key_findings": analysis.key_findings,
        "indicators_of_compromise": analysis.indicators_of_compromise,
        "initial_access_vector": analysis.initial_access_vector,
        "affected_assets": analysis.affected_assets,
        "observed_techniques": analysis.observed_techniques,
        "honeypot_engagement": analysis.honeypot_engagement,
        "simulated_data_loss": analysis.simulated_data_loss,
        "overall_risk_score": analysis.overall_risk_score,
        "recommended_actions": analysis.recommended_actions,
        "graph_nodes": context.get("graph_nodes", []),
        "graph_edges": context.get("graph_edges", []),
    }


async def _analyze(inc) -> AIIncidentAnalysis:
    """Analyze an incident without blocking FastAPI's event loop."""
    settings = get_settings()

    if not settings.gemini_api_key:
        logger.info("Gemini is not configured; using deterministic report fallback")
        return fallback_analysis(inc)

    try:
        return await asyncio.to_thread(
            analyze_incident,
            inc,
            api_key=settings.gemini_api_key,
            model=settings.gemini_model,
        )
    except Exception:
        logger.exception("Gemini incident analysis failed for %s", inc.incident_id)
        return fallback_analysis(inc)


@router.get("")
async def list_reports(
    repo: Annotated[PostgresIncidentRepository, Depends(get_incident_repository)],
    _user: Annotated[TokenPayload, Depends(get_current_user)],
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    """List lightweight investigation report records."""
    incidents = await repo.list_all(limit=limit, offset=offset)
    reports = []
    for inc in incidents:
        context = inc.context or {}
        reports.append(
            {
                "report_id": f"REP-{inc.incident_id}",
                "incident_id": inc.incident_id,
                "title": inc.title,
                "severity": inc.severity.value,
                "status": inc.status.value,
                "created_at": inc.created_at.isoformat(),
                "updated_at": inc.updated_at.isoformat(),
                "executive_summary": context.get(
                    "executive_summary", "Open the incident to run Gemini AI analysis."
                ),
                "overall_risk_score": context.get("overall_risk_score", 0),
                "observed_techniques_count": len(context.get("observed_techniques", [])),
                "affected_assets": context.get("affected_assets", []),
            }
        )
    return reports


@router.get("/{incident_id}")
async def get_report_detail(
    incident_id: str,
    repo: Annotated[PostgresIncidentRepository, Depends(get_incident_repository)],
    _user: Annotated[TokenPayload, Depends(get_current_user)],
):
    """Generate and return a live Gemini investigation for one incident."""
    inc = await repo.get_by_id(incident_id)
    if inc is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report for incident '{incident_id}' not found.",
        )

    analysis = await _analyze(inc)
    return _report_fields(inc, analysis)
