"""Postgres / Async SQLAlchemy repository for managed assets / endpoint agents."""

from __future__ import annotations

from typing import Any
from sqlalchemy import desc, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models.agent import AgentModel


class PostgresAgentRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def upsert_agent(self, agent_data: dict[str, Any]) -> AgentModel:
        agent_id = agent_data["agent_id"]
        existing = await self._session.get(AgentModel, agent_id)
        if existing:
            for k, v in agent_data.items():
                if hasattr(existing, k):
                    setattr(existing, k, v)
            model = existing
        else:
            model = AgentModel(**agent_data)
            self._session.add(model)

        await self._session.commit()
        await self._session.refresh(model)
        return model

    async def list_agents(
        self,
        limit: int = 50,
        offset: int = 0,
        *,
        status: str | None = None,
        asset_type: str | None = None,
        criticality: str | None = None,
        environment: str | None = None,
        internet_exposed: bool | None = None,
        query: str | None = None,
    ) -> list[dict[str, Any]]:
        stmt = select(AgentModel)
        if status:
            stmt = stmt.where(AgentModel.status == status.upper())
        if asset_type:
            stmt = stmt.where(AgentModel.asset_type == asset_type.upper())
        if criticality:
            stmt = stmt.where(AgentModel.criticality == criticality.upper())
        if environment:
            stmt = stmt.where(AgentModel.environment == environment.upper())
        if internet_exposed is not None:
            stmt = stmt.where(AgentModel.internet_exposed == internet_exposed)
        if query:
            pattern = f"%{query.strip()}%"
            stmt = stmt.where(
                or_(
                    AgentModel.hostname.ilike(pattern),
                    AgentModel.ip_address.ilike(pattern),
                    AgentModel.os.ilike(pattern),
                    AgentModel.owner.ilike(pattern),
                )
            )
        stmt = stmt.order_by(desc(AgentModel.risk_score), AgentModel.hostname).limit(limit).offset(offset)
        result = await self._session.execute(stmt)
        return [row.to_dict() for row in result.scalars().all()]

    async def get_agent(self, agent_id: str) -> dict[str, Any] | None:
        model = await self._session.get(AgentModel, agent_id)
        return model.to_dict() if model else None

    async def get_agent_model(self, agent_id: str) -> AgentModel | None:
        return await self._session.get(AgentModel, agent_id)

    async def update_asset_metadata(self, agent_id: str, changes: dict[str, Any]) -> dict[str, Any] | None:
        model = await self._session.get(AgentModel, agent_id)
        if model is None:
            return None
        allowed = {"asset_type", "criticality", "environment", "owner", "internet_exposed", "tags"}
        for key, value in changes.items():
            if key in allowed:
                setattr(model, key, value)
        await self._session.commit()
        await self._session.refresh(model)
        return model.to_dict()

    async def get_agent_by_ip(self, ip_address: str | None) -> dict[str, Any] | None:
        if not ip_address:
            return None
        result = await self._session.execute(
            select(AgentModel).where(AgentModel.ip_address == ip_address).limit(1)
        )
        model = result.scalar_one_or_none()
        return model.to_dict() if model else None
