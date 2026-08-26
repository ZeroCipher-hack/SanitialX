"""
Postgres / Async SQLAlchemy repository for Endpoint Agents.
"""

from __future__ import annotations

from typing import Any
from sqlalchemy import select
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
                setattr(existing, k, v)
            model = existing
        else:
            model = AgentModel(**agent_data)
            self._session.add(model)

        await self._session.commit()
        await self._session.refresh(model)
        return model

    async def list_agents(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        stmt = select(AgentModel).order_by(AgentModel.hostname).limit(limit).offset(offset)
        result = await self._session.execute(stmt)
        return [row[0].to_dict() for row in result.all()]

    async def get_agent(self, agent_id: str) -> dict[str, Any] | None:
        model = await self._session.get(AgentModel, agent_id)
        return model.to_dict() if model else None
