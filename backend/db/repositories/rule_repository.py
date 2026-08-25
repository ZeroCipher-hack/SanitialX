"""
Postgres implementation of DetectionRuleRepository interface.
"""

from __future__ import annotations

from typing import Any, Sequence

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from db.models.rule import DetectionRuleORM


class PostgresDetectionRuleRepository:
    """Repository for persistent detection rule metadata and configuration."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def save_rule(
        self,
        rule_id: str,
        rule_name: str,
        severity: str,
        description: str | None = None,
        enabled: bool = True,
        parameters: dict[str, Any] | None = None,
    ) -> None:
        async with self._session_factory() as session:
            stmt = select(DetectionRuleORM).where(DetectionRuleORM.rule_id == rule_id)
            existing = (await session.execute(stmt)).scalar_one_or_none()

            if existing is None:
                orm = DetectionRuleORM(
                    rule_id=rule_id,
                    rule_name=rule_name,
                    description=description,
                    severity=severity,
                    enabled=enabled,
                    parameters=parameters or {},
                )
                session.add(orm)
            else:
                existing.rule_name = rule_name
                existing.severity = severity
                existing.description = description
                existing.enabled = enabled
                existing.parameters = parameters or {}

            await session.commit()

    async def get_rule(self, rule_id: str) -> dict[str, Any] | None:
        async with self._session_factory() as session:
            stmt = select(DetectionRuleORM).where(DetectionRuleORM.rule_id == rule_id)
            orm = (await session.execute(stmt)).scalar_one_or_none()
            if orm is None:
                return None
            return {
                "rule_id": orm.rule_id,
                "rule_name": orm.rule_name,
                "description": orm.description,
                "severity": orm.severity,
                "enabled": orm.enabled,
                "parameters": orm.parameters,
                "created_at": orm.created_at,
                "updated_at": orm.updated_at,
            }

    async def list_rules(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        async with self._session_factory() as session:
            stmt = select(DetectionRuleORM).limit(limit).offset(offset)
            orms = (await session.execute(stmt)).scalars().all()
            return [
                {
                    "rule_id": o.rule_id,
                    "rule_name": o.rule_name,
                    "description": o.description,
                    "severity": o.severity,
                    "enabled": o.enabled,
                    "parameters": o.parameters,
                    "created_at": o.created_at,
                    "updated_at": o.updated_at,
                }
                for o in orms
            ]
