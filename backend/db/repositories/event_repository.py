"""
Postgres / Async SQLAlchemy repository for Security Events.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from sqlalchemy import or_, select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from db.models.event import EventModel


class PostgresEventRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add_event(self, event_data: dict[str, Any]) -> EventModel:
        model = EventModel(**event_data)
        self._session.add(model)
        await self._session.commit()
        await self._session.refresh(model)
        return model

    async def list_events(
        self,
        limit: int = 100,
        offset: int = 0,
        severity: str | None = None,
        event_type: str | None = None,
        source_ip: str | None = None,
    ) -> list[dict[str, Any]]:
        stmt = select(EventModel).order_by(desc(EventModel.timestamp))
        if severity and severity.upper() != "ALL":
            stmt = stmt.where(EventModel.severity == severity.upper())
        if event_type and event_type.upper() != "ALL":
            stmt = stmt.where(EventModel.event_type == event_type)
        if source_ip:
            stmt = stmt.where(EventModel.source_ip == source_ip)

        stmt = stmt.limit(limit).offset(offset)
        result = await self._session.execute(stmt)
        return [row[0].to_dict() for row in result.all()]

    async def list_asset_events(
        self,
        *,
        hostname: str | None,
        ip_address: str | None,
        since: datetime,
        limit: int = 500,
    ) -> list[EventModel]:
        """Return recent events tied to an asset by host or destination IP."""
        identities = []
        if hostname:
            identities.append(EventModel.host == hostname)
        if ip_address:
            identities.append(EventModel.destination_ip == ip_address)
        if not identities:
            return []

        stmt = (
            select(EventModel)
            .where(EventModel.timestamp >= since, or_(*identities))
            .order_by(desc(EventModel.timestamp))
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def count_events(self) -> int:
        stmt = select(EventModel)
        result = await self._session.execute(stmt)
        return len(result.all())
