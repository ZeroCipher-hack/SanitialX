"""
Postgres implementation of IncidentRepository interface.

CRITICAL INVARIANT:
Optimistic concurrency control is strictly enforced on update.
Update executes: UPDATE incidents ... WHERE incident_id = :id AND version = :expected_version
If 0 rows are affected, raises IncidentConflictError.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Sequence

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from core.errors import IncidentConflictError
from correlation.enums import Severity
from db.models.incident import IncidentORM
from incidents.enums import IncidentStatus
from incidents.models import Incident
from incidents.repository import IncidentRepository


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _orm_to_domain(orm: IncidentORM) -> Incident:
    return Incident(
        incident_id=orm.incident_id,
        title=orm.title,
        description=orm.description,
        severity=Severity(orm.severity),
        status=IncidentStatus(orm.status),
        version=orm.version,
        created_at=_ensure_utc(orm.created_at),
        updated_at=_ensure_utc(orm.updated_at),
        source_ip=orm.source_ip,
        destination_ip=orm.destination_ip,
        triggering_detection_ids=orm.triggering_detection_ids or [],
        context=orm.context or {},
    )


class PostgresIncidentRepository(IncidentRepository):
    """Postgres / SQLAlchemy implementation of IncidentRepository."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession] | AsyncSession) -> None:
        self._session_factory = session_factory

    def _get_session(self):
        from contextlib import asynccontextmanager
        @asynccontextmanager
        async def _ctx():
            if isinstance(self._session_factory, AsyncSession):
                yield self._session_factory
            else:
                async with self._session_factory() as s:
                    yield s
        return _ctx()

    async def create(self, incident: Incident) -> Incident:
        async with self._get_session() as session:
            orm = IncidentORM(
                incident_id=incident.incident_id,
                title=incident.title,
                description=incident.description,
                severity=incident.severity.value,
                status=incident.status.value,
                version=incident.version,
                created_at=incident.created_at,
                updated_at=incident.updated_at,
                source_ip=incident.source_ip,
                destination_ip=incident.destination_ip,
                triggering_detection_ids=incident.triggering_detection_ids,
                context=incident.context,
            )
            session.add(orm)
            await session.commit()
            await session.refresh(orm)
            return _orm_to_domain(orm)

    async def get_by_id(self, incident_id: str) -> Incident | None:
        async with self._get_session() as session:
            result = await session.execute(
                select(IncidentORM).where(IncidentORM.incident_id == incident_id)
            )
            orm = result.scalar_one_or_none()
            if orm is None:
                return None
            return _orm_to_domain(orm)

    async def update(self, incident: Incident, expected_version: int) -> Incident:
        """Update incident enforcing optimistic concurrency control.

        Executes UPDATE ... WHERE incident_id = :id AND version = :expected_version.
        """
        async with self._get_session() as session:
            stmt = (
                update(IncidentORM)
                .where(
                    IncidentORM.incident_id == incident.incident_id,
                    IncidentORM.version == expected_version,
                )
                .values(
                    title=incident.title,
                    description=incident.description,
                    severity=incident.severity.value,
                    status=incident.status.value,
                    version=incident.version,
                    updated_at=incident.updated_at,
                    source_ip=incident.source_ip,
                    destination_ip=incident.destination_ip,
                    triggering_detection_ids=incident.triggering_detection_ids,
                    context=incident.context,
                )
            )
            result = await session.execute(stmt)
            await session.commit()

            if result.rowcount == 0:
                # Determine if incident exists or version mismatched
                check_result = await session.execute(
                    select(IncidentORM.version).where(
                        IncidentORM.incident_id == incident.incident_id
                    )
                )
                current_version = check_result.scalar_one_or_none()
                if current_version is None:
                    raise KeyError(f"Incident '{incident.incident_id}' not found.")
                raise IncidentConflictError(
                    f"Concurrency conflict updating incident '{incident.incident_id}': "
                    f"expected version {expected_version}, but database version is {current_version}."
                )

            # Fetch updated object
            updated_orm = await session.scalar(
                select(IncidentORM).where(IncidentORM.incident_id == incident.incident_id)
            )
            assert updated_orm is not None
            return _orm_to_domain(updated_orm)

    async def list_all(self, limit: int = 100, offset: int = 0) -> list[Incident]:
        async with self._get_session() as session:
            stmt = (
                select(IncidentORM)
                .order_by(IncidentORM.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
            result = await session.execute(stmt)
            orms = result.scalars().all()
            return [_orm_to_domain(o) for o in orms]
