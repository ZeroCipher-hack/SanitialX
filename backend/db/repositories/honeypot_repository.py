"""
Postgres / Async SQLAlchemy repository for Honeypot Sessions.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from db.models.honeypot import HoneypotSessionModel


class PostgresHoneypotRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def recent_sessions(self, *, within_hours: int = 24) -> list[HoneypotSessionModel]:
        """Honeypot sessions that started within the window (newest first)."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=max(1, within_hours))
        stmt = (
            select(HoneypotSessionModel)
            .where(HoneypotSessionModel.started_at >= cutoff)
            .order_by(desc(HoneypotSessionModel.started_at))
        )
        result = await self._session.execute(stmt)
        return [row[0] for row in result.all()]

    async def add_session(self, session_data: dict[str, Any]) -> HoneypotSessionModel:
        model = HoneypotSessionModel(**session_data)
        self._session.add(model)
        await self._session.commit()
        await self._session.refresh(model)
        return model

    async def list_sessions(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        stmt = select(HoneypotSessionModel).order_by(desc(HoneypotSessionModel.started_at)).limit(limit).offset(offset)
        result = await self._session.execute(stmt)
        return [row[0].to_dict() for row in result.all()]

    async def get_session(self, session_id: str) -> dict[str, Any] | None:
        model = await self._session.get(HoneypotSessionModel, session_id)
        return model.to_dict() if model else None
