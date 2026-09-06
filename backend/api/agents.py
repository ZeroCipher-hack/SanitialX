"""Managed assets / endpoint agents API router for SanitialX."""

from __future__ import annotations

import hmac
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_current_user, get_db_session, require_role
from core.config import get_settings
from core.security import (
    TokenPayload,
    generate_agent_token,
    hash_agent_token,
    verify_agent_token,
)
from db.repositories.agent_repository import PostgresAgentRepository
from db.repositories.vulnerability_repository import PostgresVulnerabilityRepository

router = APIRouter(prefix="/agents", tags=["Assets & Endpoints"])


class AgentEnrollmentPayload(BaseModel):
    agent_id: str = Field(..., min_length=3, max_length=64)
    hostname: str = Field(..., min_length=1, max_length=100)
    ip_address: str = Field(..., min_length=3, max_length=45)
    os: str = Field(..., min_length=1, max_length=100)
    agent_version: str | None = Field(default=None, max_length=40)


class AgentHeartbeatPayload(BaseModel):
    cpu_usage: float = Field(default=0.0, ge=0, le=100)
    memory_usage: float = Field(default=0.0, ge=0, le=100)
    agent_version: str | None = Field(default=None, max_length=40)
    ip_address: str | None = Field(default=None, min_length=3, max_length=45)


class SoftwareInventoryItem(BaseModel):
    vendor: str = Field(default="", max_length=120)
    product: str = Field(..., min_length=1, max_length=160)
    version: str = Field(..., min_length=1, max_length=80)
    package_name: str | None = Field(default=None, max_length=180)
    ecosystem: str | None = Field(default=None, max_length=40)
    purl: str | None = Field(default=None, max_length=512)
    cpe: str | None = Field(default=None, max_length=512)
    source: str = Field(default="agent", max_length=40)

    @field_validator("ecosystem")
    @classmethod
    def normalize_ecosystem(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip().lower()
        return normalized or None

    @field_validator("purl")
    @classmethod
    def validate_purl(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if normalized and not normalized.startswith("pkg:"):
            raise ValueError("purl must start with 'pkg:'")
        return normalized or None

    @field_validator("cpe")
    @classmethod
    def validate_cpe(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if normalized and not normalized.startswith("cpe:2.3:"):
            raise ValueError("cpe must use CPE 2.3 format")
        return normalized or None


class SoftwareInventoryPayload(BaseModel):
    software: list[SoftwareInventoryItem] = Field(default_factory=list, max_length=5000)


class AssetMetadataUpdate(BaseModel):
    asset_type: Literal["ENDPOINT", "SERVER", "WORKSTATION", "CLOUD", "NETWORK", "CONTAINER", "OTHER"] | None = None
    criticality: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None
    environment: Literal["PRODUCTION", "STAGING", "DEVELOPMENT", "TEST", "UNKNOWN"] | None = None
    lifecycle_status: Literal["DISCOVERED", "MANAGED", "RETIRED", "EXCLUDED"] | None = None
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


@router.post("/enroll", status_code=status.HTTP_201_CREATED)
async def enroll_agent(
    payload: AgentEnrollmentPayload,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    enrollment_key: Annotated[str | None, Header(alias="X-Enrollment-Key")] = None,
) -> dict[str, Any]:
    """Enroll or rotate credentials for an endpoint agent using the bootstrap enrollment key."""
    settings = get_settings()
    if not enrollment_key or not hmac.compare_digest(enrollment_key, settings.api_key):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid enrollment key.")

    raw_token = generate_agent_token()
    model = await PostgresAgentRepository(session).enroll_agent(
        payload.model_dump(), hash_agent_token(raw_token)
    )
    return {
        "agent_id": model.agent_id,
        "agent_token": raw_token,
        "status": model.status,
        "enrolled_at": model.enrolled_at.isoformat() if model.enrolled_at else None,
        "heartbeat_interval_seconds": 30,
    }


@router.post("/{agent_id}/heartbeat")
async def agent_heartbeat(
    agent_id: str,
    payload: AgentHeartbeatPayload,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    agent_token: Annotated[str | None, Header(alias="X-Agent-Token")] = None,
) -> dict[str, Any]:
    """Authenticated endpoint heartbeat carrying health telemetry."""
    repo = PostgresAgentRepository(session)
    model = await repo.get_agent_model(agent_id)
    if model is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found.")
    if not agent_token or not verify_agent_token(agent_token, model.agent_token_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid agent token.")

    updated = await repo.heartbeat_agent(
        agent_id,
        cpu_usage=payload.cpu_usage,
        memory_usage=payload.memory_usage,
        agent_version=payload.agent_version,
        ip_address=payload.ip_address,
    )
    assert updated is not None
    return {
        "agent_id": updated.agent_id,
        "status": updated.status,
        "last_seen": updated.last_seen.isoformat(),
        "next_heartbeat_seconds": 30,
    }


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
    lifecycle_status: str | None = None,
    internet_exposed: bool | None = None,
    q: str | None = Query(default=None, max_length=160),
):
    repo = PostgresAgentRepository(session)
    return await repo.list_agents(
        limit=limit, offset=offset, status=status_filter, asset_type=asset_type,
        criticality=criticality, environment=environment, lifecycle_status=lifecycle_status,
        internet_exposed=internet_exposed, query=q,
    )


@router.get("/summary")
async def get_asset_summary(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _user: Annotated[TokenPayload, Depends(get_current_user)],
    stale_after_hours: int = Query(default=24, ge=1, le=720),
) -> dict[str, int]:
    return await PostgresAgentRepository(session).get_inventory_summary(stale_after_hours=stale_after_hours)


@router.get("/{agent_id}")
async def get_asset_detail(
    agent_id: str,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _user: Annotated[TokenPayload, Depends(get_current_user)],
) -> dict[str, Any]:
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
            "total": len(exposures), "affected": len(affected), "critical": len(critical),
            "high": len(high), "max_risk_score": max((item.risk_score for item in exposures), default=0),
        },
        "top_exposures": [
            {"cve_id": item.cve_id, "status": item.status, "risk_score": item.risk_score,
             "match_confidence": item.match_confidence, "internet_exposed": item.internet_exposed,
             "matched_software": item.matched_software}
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
    updated = await PostgresAgentRepository(session).update_asset_metadata(agent_id, payload.model_dump(exclude_unset=True))
    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Asset '{agent_id}' not found.")
    return updated


def _software_to_dict(item: Any) -> dict[str, Any]:
    return {"vendor":item.vendor,"product":item.product,"version":item.version,"package_name":item.package_name,"ecosystem":item.ecosystem,"purl":item.purl,"cpe":item.cpe,"source":item.source,"last_seen":item.last_seen}


@router.put("/{agent_id}/software")
async def replace_software_inventory(
    agent_id: str,
    payload: SoftwareInventoryPayload,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _user: Annotated[TokenPayload, Depends(get_current_user)],
) -> dict[str, Any]:
    agent_repo = PostgresAgentRepository(session)
    if await agent_repo.get_agent(agent_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Agent '{agent_id}' not found.")
    repo = PostgresVulnerabilityRepository(session)
    items = await repo.replace_software_inventory(agent_id, [item.model_dump() for item in payload.software])
    asset = await agent_repo.touch_inventory(agent_id)
    return {"agent_id":agent_id,"software_count":len(items),"inventory_updated_at":asset.get("inventory_updated_at") if asset else None,"lifecycle_status":asset.get("lifecycle_status") if asset else None,"software":[_software_to_dict(item) for item in items]}


@router.get("/{agent_id}/software")
async def get_software_inventory(
    agent_id: str,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _user: Annotated[TokenPayload, Depends(get_current_user)],
) -> dict[str, Any]:
    agent_repo = PostgresAgentRepository(session)
    if await agent_repo.get_agent(agent_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Agent '{agent_id}' not found.")
    items = await PostgresVulnerabilityRepository(session).list_software_inventory(agent_id)
    return {"agent_id":agent_id,"software_count":len(items),"software":[_software_to_dict(item) for item in items]}
