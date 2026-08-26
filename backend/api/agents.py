"""
Endpoint Agents API Router for SanitialX.
"""

from __future__ import annotations

from typing import Annotated
from fastapi import APIRouter, Depends, Query

from api.deps import get_current_user, get_db_session
from core.security import TokenPayload
from db.repositories.agent_repository import PostgresAgentRepository
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter(prefix="/agents", tags=["Agents & Endpoints"])


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
