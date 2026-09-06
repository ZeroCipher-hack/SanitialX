"""
Postgres / Async SQLAlchemy repository for Security Events.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from sqlalchemy import or_, select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from db.models.event import EventModel
from events.models import NormalizedEvent


class PostgresEventRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add_event(self, event_data: dict[str, Any]) -> EventModel:
        model = EventModel(**event_data)
        self._session.add(model)
        await self._session.commit()
        await self._session.refresh(model)
        return model

    async def persist_normalized_event(self, event: NormalizedEvent) -> tuple[EventModel, bool]:
        """Persist a live NormalizedEvent once, keyed by immutable event_id.

        Returns ``(model, created)`` so callers can distinguish a fresh write
        from a replayed Redis/event-bus delivery without raising a duplicate
        primary-key error.
        """
        existing = await self._session.get(EventModel, event.event_id)
        if existing is not None:
            return existing, False

        metadata = event.metadata or {}
        severity = str(metadata.get("severity") or "INFO").upper()
        if severity not in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            severity = "INFO"

        details = metadata.get("details") or metadata.get("message")
        model = EventModel(
            event_id=event.event_id,
            timestamp=event.timestamp,
            event_type=event.event_type,
            severity=severity,
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            user=metadata.get("user") or metadata.get("username"),
            host=metadata.get("host") or metadata.get("hostname"),
            rule_id=metadata.get("rule_id"),
            mitre_technique=metadata.get("mitre_technique"),
            details=str(details) if details is not None else None,
            raw_payload={
                "sensor_id": event.sensor_id,
                "source_port": event.source_port,
                "destination_port": event.destination_port,
                "protocol": event.protocol,
                "metadata": metadata,
            },
        )
        self._session.add(model)
        await self._session.commit()
        await self._session.refresh(model)
        return model, True

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
