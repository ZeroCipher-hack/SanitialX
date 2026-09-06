"""Managed assets / endpoint agents API router for SanitialX."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_current_user, get_db_session, require_role
from core.security import TokenPayload
from db.repositories.agent_repository import PostgresAgentRepository
from db.repositories.vulnerability_repository import PostgresVulnerabilityRepository

router = APIRouter(prefix="/agents", tags=["Assets & Endpoints"])


class SoftwareInventoryItem(BaseModel):
    vendor: str = ""
    product: str = Field(..., min_length=1, max_length=160)
    version: str = Field(..., min_length=1, max_length=80)
    package_name: str | None = Field(default=None, max_length=180)
    source: str = Field(default="agent", max_length=40)


class SoftwareInventoryPayload(BaseModel):
    software: list[SoftwareInventoryItem] = Field(default_factory=list, max_length=5000)


class AssetMetadataUpdate(BaseModel):
    asset_type: Literal["ENDPOINT", "SERVER", "WORKSTATION", "CLOUD", "NETWORK", "CONTAINER", "OTHER"] | None = None
    criticality: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None
    environment: Literal["PRODUCTION", "STAGING", "DEVELOPMENT", "TEST", "UNKNOWN"] | None = None
    owner: str | None = Field(default=None, max_length=160)
    internet_exposed: bool | None = None
    tags: list[str] | None = Field(default=None, max_length=50)

    @field_validator("tags")
    @classmethod
    def normalize_tags(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        cleaned = [item.strip().lower() for item in value if item.strip()]
        if any(len(item) > 64 for item in cleaned):
            raise ValueError("each tag must be at most 64 characters")
        return list(dict.fromkeys(cleaned))


@router.get("")
async def list_agents(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _user: Annotated[TokenPayload, Depends(get_current_user)],
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    status_filter: str | None = Query(default=None, alias="status"),
    asset_type: str | None = None,
    criticality: str | None = None,
    environment: str | None = None,
    internet_exposed: bool | None = None,
    q: str | None = Query(default=None, max_length=160),
):
    """List managed assets with SOC inventory filters."""
    repo = PostgresAgentRepository(session)
    return await repo.list_agents(
        limit=limit,
        offset=offset,
        status=status_filter,
        asset_type=asset_type,
        criticality=criticality,
        environment=environment,
        internet_exposed=internet_exposed,
        query=q,
    )


@router.get("/summary")
async def get_asset_summary(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _user: Annotated[TokenPayload, Depends(get_current_user)],
) -> dict[str, int]:
    """Return inventory coverage counters for the SOC dashboard."""
    return await PostgresAgentRepository(session).get_inventory_summary()


@router.get("/{agent_id}")
async def get_asset_detail(
    agent_id: str,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _user: Annotated[TokenPayload, Depends(get_current_user)],
) -> dict[str, Any]:
    """Return asset identity, software inventory, and vulnerability exposure summary."""
    agent_repo = PostgresAgentRepository(session)
    asset = await agent_repo.get_agent(agent_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Asset '{agent_id}' not found.")

    vuln_repo = PostgresVulnerabilityRepository(session)
    software = await vuln_repo.list_software_inventory(agent_id)
    exposures = await vuln_repo.list_asset_exposures(agent_id=agent_id, limit=500)
    affected = [item for item in exposures if item.status == "AFFECTED"]
    critical = [item for item in exposures if item.risk_score >= 90]
    high = [item for item in exposures if 70 <= item.risk_score < 90]

    return {
        **asset,
        "software_count": len(software),
        "exposure_summary": {
            "total": len(exposures),
            "affected": len(affected),
            "critical": len(critical),
            "high": len(high),
            "max_risk_score": max((item.risk_score for item in exposures), default=0),
        },
        "top_exposures": [
            {
                "cve_id": item.cve_id,
                "status": item.status,
                "risk_score": item.risk_score,
                "match_confidence": item.match_confidence,
                "internet_exposed": item.internet_exposed,
                "matched_software": item.matched_software,
            }
            for item in exposures[:10]
        ],
    }


@router.patch("/{agent_id}")
async def update_asset_metadata(
    agent_id: str,
    payload: AssetMetadataUpdate,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _user: Annotated[TokenPayload, Depends(require_role(["admin", "analyst"]))],
) -> dict[str, Any]:
    """Manage SOC-owned asset metadata without overwriting agent telemetry fields."""
    changes = payload.model_dump(exclude_unset=True)
    repo = PostgresAgentRepository(session)
    updated = await repo.update_asset_metadata(agent_id, changes)
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Asset '{agent_id}' not found.")
    return updated


@router.put("/{agent_id}/software")
async def replace_software_inventory(
    agent_id: str,
    payload: SoftwareInventoryPayload,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _user: Annotated[TokenPayload, Depends(get_current_user)],
) -> dict[str, Any]:
    """Replace an endpoint's observed software inventory atomically."""
    agent_repo = PostgresAgentRepository(session)
    if await agent_repo.get_agent(agent_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Agent '{agent_id}' not found.")

    repo = PostgresVulnerabilityRepository(session)
    items = await repo.replace_software_inventory(agent_id, [item.model_dump() for item in payload.software])
    return {
        "agent_id": agent_id,
        "software_count": len(items),
        "software": [
            {
                "vendor": item.vendor,
                "product": item.product,
                "version": item.version,
                "package_name": item.package_name,
                "source": item.source,
                "last_seen": item.last_seen,
            }
            for item in items
        ],
    }


@router.get("/{agent_id}/software")
async def get_software_inventory(
    agent_id: str,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _user: Annotated[TokenPayload, Depends(get_current_user)],
) -> dict[str, Any]:
    agent_repo = PostgresAgentRepository(session)
    if await agent_repo.get_agent(agent_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Agent '{agent_id}' not found.")

    repo = PostgresVulnerabilityRepository(session)
    items = await repo.list_software_inventory(agent_id)
    return {
        "agent_id": agent_id,
        "software_count": len(items),
        "software": [
            {
                "vendor": item.vendor,
                "product": item.product,
                "version": item.version,
                "package_name": item.package_name,
                "source": item.source,
                "last_seen": item.last_seen,
            }
            for item in items
        ],
    }
