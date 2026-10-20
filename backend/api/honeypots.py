"""
Honeypot & Deception API Router for SanitialX.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_current_user, get_db_session, require_role
from core.security import TokenPayload
from db.repositories.honeypot_repository import PostgresHoneypotRepository

router = APIRouter(prefix="/honeypots", tags=["Honeypots & Deception"])


class HoneypotEventCreate(BaseModel):
    """One attacker interaction reported by a decoy/low-interaction honeypot."""

    attacker_ip: str = Field(..., min_length=3, max_length=45)
    service: str = Field(..., min_length=1, max_length=50)
    credentials_attempted: list[str] = Field(default_factory=list)
    commands_executed: list[str] = Field(default_factory=list)
    files_accessed: list[str] = Field(default_factory=list)
    duration_seconds: int = Field(default=0, ge=0)
    risk_score: int = Field(default=50, ge=0, le=100)
    notes: str | None = Field(default=None, max_length=2000)


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


@router.post("/events", status_code=status.HTTP_201_CREATED)
async def record_honeypot_event(
    payload: HoneypotEventCreate,
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _user: Annotated[TokenPayload, Depends(require_role(["admin", "analyst"]))],
):
    """Record a honeypot interaction.

    This is the local real-time attack signal: a hit here marks its service
    category as "under active attack", which boosts the risk of exposures on
    that service the next time an asset is evaluated.
    """
    repo = PostgresHoneypotRepository(session)
    model = await repo.add_session(
        {
            "session_id": str(uuid.uuid4()),
            "attacker_ip": payload.attacker_ip,
            "service": payload.service,
            "started_at": datetime.now(timezone.utc),
            "duration_seconds": payload.duration_seconds,
            "credentials_attempted": payload.credentials_attempted,
            "commands_executed": payload.commands_executed,
            "files_accessed": payload.files_accessed,
            "risk_score": payload.risk_score,
            "notes": payload.notes,
        }
    )
    return model.to_dict()
