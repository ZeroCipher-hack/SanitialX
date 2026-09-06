"""
Endpoint Agents API Router for SanitialX.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_current_user, get_db_session
from core.security import TokenPayload
from db.repositories.agent_repository import PostgresAgentRepository
from db.repositories.vulnerability_repository import PostgresVulnerabilityRepository

router = APIRouter(prefix="/agents", tags=["Agents & Endpoints"])


class SoftwareInventoryItem(BaseModel):
    vendor: str = ""
    product: str = Field(..., min_length=1, max_length=160)
    version: str = Field(..., min_length=1, max_length=80)
    package_name: str | None = Field(default=None, max_length=180)
    source: str = Field(default="agent", max_length=40)


class SoftwareInventoryPayload(BaseModel):
    software: list[SoftwareInventoryItem] = Field(default_factory=list, max_length=5000)


@router.get("")
async def list_agents(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _user: Annotated[TokenPayload, Depends(get_current_user)],
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    """List managed endpoint agents and their status."""
    repo = PostgresAgentRepository(session)
    return await repo.list_agents(limit=limit, offset=offset)


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
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_id}' not found.",
        )

    repo = PostgresVulnerabilityRepository(session)
    items = await repo.replace_software_inventory(
        agent_id,
        [item.model_dump() for item in payload.software],
    )
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
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{agent_id}' not found.",
        )

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
