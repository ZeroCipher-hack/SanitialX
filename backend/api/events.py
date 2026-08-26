"""
Security Events API Router for SanitialX.
"""

from __future__ import annotations

from typing import Annotated
from fastapi import APIRouter, Depends, Query

from api.deps import get_current_user, get_db_session
from core.security import TokenPayload
from db.repositories.event_repository import PostgresEventRepository
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter(prefix="/events", tags=["Security Events"])


@router.get("")
async def list_events(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _user: Annotated[TokenPayload, Depends(get_current_user)],
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    severity: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    source_ip: str | None = Query(default=None),
):
    """List security events from the telemetry store."""
    repo = PostgresEventRepository(session)
    events = await repo.list_events(
        limit=limit,
        offset=offset,
        severity=severity,
        event_type=event_type,
        source_ip=source_ip,
    )
    return events
