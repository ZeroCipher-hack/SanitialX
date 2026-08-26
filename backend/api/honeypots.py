"""
Honeypot & Deception API Router for SanitialX.
"""

from __future__ import annotations

from typing import Annotated
from fastapi import APIRouter, Depends, Query

from api.deps import get_current_user, get_db_session
from core.security import TokenPayload
from db.repositories.honeypot_repository import PostgresHoneypotRepository
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter(prefix="/honeypots", tags=["Honeypots & Deception"])


@router.get("")
async def list_honeypot_sessions(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _user: Annotated[TokenPayload, Depends(get_current_user)],
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    """List honeypot deception sessions and attacker interaction logs."""
    repo = PostgresHoneypotRepository(session)
    return await repo.list_sessions(limit=limit, offset=offset)
