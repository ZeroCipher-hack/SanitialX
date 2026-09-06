"""Vulnerability Intelligence API for SanitialX."""

from __future__ import annotations

import asyncio
import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_current_user, get_db_session, require_role
from core.config import get_settings
from core.security import TokenPayload
from db.repositories.agent_repository import PostgresAgentRepository
from db.repositories.vulnerability_repository import PostgresVulnerabilityRepository
from services.ai_vulnerability_analysis import (
    analyze_vulnerability,
    fallback_vulnerability_analysis,
)
from vulnerabilities.correlation import VulnerabilityEventCorrelator
from vulnerabilities.service import VulnerabilityService
from vulnerabilities.sync import VulnerabilitySyncService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerability Intelligence"])


def _vulnerability_to_dict(model) -> dict[str, Any]:
    return {
        "cve_id": model.cve_id,
        "summary": model.summary,
        "cvss_score": model.cvss_score,
        "severity": model.severity,
        "published_at": model.published_at,
        "modified_at": model.modified_at,
        "known_exploited": model.known_exploited,
        "exploit_available": model.exploit_available,
        "affected_products": model.affected_products,
        "references": model.references,
        "source": model.source,
        "ingested_at": model.ingested_at,
    }


def _exposure_to_dict(model) -> dict[str, Any]:
    return {
        "id": model.id,
        "agent_id": model.agent_id,
        "cve_id": model.cve_id,
        "status": model.status,
        "match_confidence": model.match_confidence,
        "risk_score": model.risk_score,
        "internet_exposed": model.internet_exposed,
        "matched_software": model.matched_software,
        "rationale": model.rationale,
        "first_seen": model.first_seen,
        "last_evaluated": model.last_evaluated,
    }


@router.get("")
async def list_vulnerabilities(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _user: Annotated[TokenPayload, Depends(get_current_user)],
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    severity: str | None = Query(default=None),
    known_exploited: bool | None = Query(default=None),
) -> list[dict[str, Any]]:
    service = VulnerabilityService(PostgresVulnerabilityRepository(session))
    items = await service.list_vulnerabilities(
        limit=limit,
        offset=offset,
        severity=severity,
        known_exploited=known_exploited,
    )
    return [_vulnerability_to_dict(item) for item in items]


@router.get("/exposures")
async def list_exposures(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _user: Annotated[TokenPayload, Depends(get_current_user)],
    agent_id: str | None = Query(default=None),
    min_risk_score: int | None = Query(default=None, ge=0, le=100),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    service = VulnerabilityService(PostgresVulnerabilityRepository(session))
    items = await service.list_exposures(
        agent_id=agent_id,
        min_risk_score=min_risk_score,
        limit=limit,
        offset=offset,
    )
    return [_exposure_to_dict(item) for item in items]


@router.post("/sync")
async def sync_vulnerabilities(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _user: Annotated[TokenPayload, Depends(require_role(["admin"]))],
    hours: int = Query(default=24, ge=1, le=720),
    max_pages: int = Query(default=10, ge=1, le=100),
) -> dict[str, Any]:
    service = VulnerabilitySyncService(PostgresVulnerabilityRepository(session))
    return await service.sync_recent(hours=hours, max_pages=max_pages)


@router.post("/evaluate/{agent_id}")
async def evaluate_agent_exposure(
    agent_id: str,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _user: Annotated[TokenPayload, Depends(get_current_user)],
    internet_exposed: bool | None = Query(
        default=None,
        description="Optional one-off override; otherwise the managed asset value is used.",
    ),
) -> dict[str, Any]:
    agent = await PostgresAgentRepository(session).get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")

    effective_internet_exposed = (
        bool(agent.get("internet_exposed")) if internet_exposed is None else internet_exposed
    )
    criticality = str(agent.get("criticality") or "MEDIUM").upper()

    service = VulnerabilityService(PostgresVulnerabilityRepository(session))
    exposures = await service.evaluate_agent(
        agent_id=agent_id,
        asset_risk_score=int(agent.get("risk_score") or 0),
        internet_exposed=effective_internet_exposed,
        criticality=criticality,
    )
    return {
        "agent_id": agent_id,
        "evaluated": True,
        "asset_context": {
            "criticality": criticality,
            "internet_exposed": effective_internet_exposed,
            "asset_risk_score": int(agent.get("risk_score") or 0),
        },
        "affected_count": len(exposures),
        "exposures": [_exposure_to_dict(item) for item in exposures],
    }


@router.post("/correlate/{agent_id}")
async def correlate_agent_exposures(
    agent_id: str,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _user: Annotated[TokenPayload, Depends(get_current_user)],
    lookback_days: int = Query(default=30, ge=1, le=365),
    create_incidents: bool = Query(default=True),
) -> dict[str, Any]:
    agent = await PostgresAgentRepository(session).get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")

    repository = PostgresVulnerabilityRepository(session)
    exposures = await repository.list_asset_exposures(agent_id=agent_id, min_risk_score=1, limit=500)
    correlator = VulnerabilityEventCorrelator(session)
    results: list[dict[str, Any]] = []

    for exposure in exposures:
        vulnerability = await repository.get_vulnerability(exposure.cve_id)
        if vulnerability is None:
            continue
        result = await correlator.correlate_exposure(
            exposure=exposure,
            vulnerability=vulnerability,
            agent=agent,
            lookback_days=lookback_days,
            create_incident=create_incidents,
        )
        results.append(result)

    return {
        "agent_id": agent_id,
        "correlated_exposures": len(results),
        "incidents_created": sum(1 for item in results if item["incident_created"]),
        "results": results,
    }


@router.post("/{cve_id}/analyze")
async def analyze_asset_vulnerability(
    cve_id: str,
    agent_id: str,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _user: Annotated[TokenPayload, Depends(get_current_user)],
) -> dict[str, Any]:
    repository = PostgresVulnerabilityRepository(session)
    vulnerability = await repository.get_vulnerability(cve_id)
    if vulnerability is None:
        raise HTTPException(status_code=404, detail=f"Vulnerability '{cve_id.upper()}' not found.")

    agent = await PostgresAgentRepository(session).get_agent(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail=f"Agent '{agent_id}' not found.")

    exposures = await repository.list_asset_exposures(agent_id=agent_id, min_risk_score=0, limit=500)
    exposure = next((item for item in exposures if item.cve_id.upper() == cve_id.upper()), None)
    if exposure is None:
        raise HTTPException(
            status_code=404,
            detail=f"No deterministic exposure exists for {agent_id} and {cve_id.upper()}.",
        )

    settings = get_settings()
    if not settings.gemini_api_key:
        analysis = fallback_vulnerability_analysis(vulnerability, exposure, agent)
    else:
        try:
            analysis = await asyncio.to_thread(
                analyze_vulnerability,
                vulnerability,
                exposure,
                agent,
                api_key=settings.gemini_api_key,
                model=settings.gemini_model,
            )
        except Exception:
            logger.exception("Gemini vulnerability analysis failed for %s/%s", cve_id, agent_id)
            analysis = fallback_vulnerability_analysis(vulnerability, exposure, agent)

    return analysis.model_dump()


@router.get("/{cve_id}")
async def get_vulnerability(
    cve_id: str,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _user: Annotated[TokenPayload, Depends(get_current_user)],
) -> dict[str, Any]:
    service = VulnerabilityService(PostgresVulnerabilityRepository(session))
    item = await service.get_vulnerability(cve_id)
    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability '{cve_id.upper()}' not found.",
        )
    return _vulnerability_to_dict(item)
