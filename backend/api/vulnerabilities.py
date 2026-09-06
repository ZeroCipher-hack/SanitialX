"""Vulnerability Intelligence API for SanitialX."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_current_user, get_db_session
from core.security import TokenPayload
from db.repositories.vulnerability_repository import PostgresVulnerabilityRepository
from vulnerabilities.service import VulnerabilityService

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
