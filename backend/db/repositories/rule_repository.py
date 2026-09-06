"""
Postgres implementation of DetectionRuleRepository interface.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from db.models.rule import DetectionRuleORM


class DetectionRuleVersionConflict(RuntimeError):
    """Raised when a stale detection-rule update attempts to overwrite newer data."""


class PostgresDetectionRuleRepository:
    """Repository for persistent detection rule metadata and configuration."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession] | AsyncSession) -> None:
        self._session_factory = session_factory

    @asynccontextmanager
    async def _get_session(self):
        if isinstance(self._session_factory, AsyncSession):
            yield self._session_factory
        else:
            async with self._session_factory() as session:
                yield session

    async def save_rule(
        self,
        rule_id: str,
        rule_name: str,
        severity: str,
        description: str | None = None,
        enabled: bool = True,
        parameters: dict[str, Any] | None = None,
        expected_version: int | None = None,
    ) -> int:
        async with self._get_session() as session:
            stmt = select(DetectionRuleORM).where(DetectionRuleORM.rule_id == rule_id)
            existing = (await session.execute(stmt)).scalar_one_or_none()
            now = datetime.now(timezone.utc)

            if existing is None:
                if expected_version not in (None, 0):
                    raise DetectionRuleVersionConflict(
                        f"Detection rule '{rule_id}' does not exist at version {expected_version}."
                    )
                version = 1
                session.add(
                    DetectionRuleORM(
                        rule_id=rule_id,
                        rule_name=rule_name,
                        description=description,
                        severity=severity,
                        enabled=enabled,
                        parameters=parameters or {},
                        version=version,
                        created_at=now,
                        updated_at=now,
                    )
                )
            else:
                current_version = int(existing.version or 1)
                if expected_version is not None and expected_version != current_version:
                    raise DetectionRuleVersionConflict(
                        f"Detection rule '{rule_id}' is version {current_version}, "
                        f"not expected version {expected_version}."
                    )
                version = current_version + 1
                existing.rule_name = rule_name
                existing.severity = severity
                existing.description = description
                existing.enabled = enabled
                if parameters is not None:
                    existing.parameters = parameters
                existing.version = version
                existing.updated_at = now

            await session.commit()
            return version

    async def get_rule(self, rule_id: str) -> dict[str, Any] | None:
        async with self._get_session() as session:
            stmt = select(DetectionRuleORM).where(DetectionRuleORM.rule_id == rule_id)
            orm = (await session.execute(stmt)).scalar_one_or_none()
            return self._to_dict(orm) if orm is not None else None

    async def list_rules(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        async with self._get_session() as session:
            stmt = (
                select(DetectionRuleORM)
                .order_by(DetectionRuleORM.rule_id.asc())
                .limit(limit)
                .offset(offset)
            )
            orms = (await session.execute(stmt)).scalars().all()
            return [self._to_dict(o) for o in orms]

    @staticmethod
    def _to_dict(orm: DetectionRuleORM) -> dict[str, Any]:
        return {
            "rule_id": orm.rule_id,
            "rule_name": orm.rule_name,
            "description": orm.description,
            "severity": orm.severity,
            "enabled": orm.enabled,
            "parameters": orm.parameters or {},
            "version": int(orm.version or 1),
            "created_at": orm.created_at,
            "updated_at": orm.updated_at,
        }
