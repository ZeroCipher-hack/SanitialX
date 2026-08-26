"""
Postgres / Async SQLAlchemy repository for Attack Simulations.
"""

from __future__ import annotations

from typing import Any
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from db.models.simulation import SimulationModel


class PostgresSimulationRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add_simulation(self, data: dict[str, Any]) -> SimulationModel:
        model = SimulationModel(**data)
        self._session.add(model)
        await self._session.commit()
        await self._session.refresh(model)
        return model

    async def list_simulations(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        stmt = select(SimulationModel).order_by(desc(SimulationModel.started_at)).limit(limit).offset(offset)
        result = await self._session.execute(stmt)
        return [row[0].to_dict() for row in result.all()]

    async def get_simulation(self, simulation_id: str) -> dict[str, Any] | None:
        model = await self._session.get(SimulationModel, simulation_id)
        return model.to_dict() if model else None
