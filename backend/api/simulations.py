"""
Attack Simulator API Router for SanitialX.
"""

from __future__ import annotations

from typing import Annotated
from fastapi import APIRouter, Depends, Query, Body

from api.deps import get_current_user, get_db_session
from core.security import TokenPayload
from db.repositories.simulation_repository import PostgresSimulationRepository
from simulation.simulator import AttackSimulatorService
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter(prefix="/simulations", tags=["Attack Simulator"])


@router.get("")
async def list_simulations(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _user: Annotated[TokenPayload, Depends(get_current_user)],
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    """List historical attack simulations run in the Cyber Range."""
    repo = PostgresSimulationRepository(session)
    return await repo.list_simulations(limit=limit, offset=offset)


@router.post("/run")
@router.post("/demo-attack")
async def run_attack_simulation(
    session: Annotated[AsyncSession, Depends(get_db_session)],
    _user: Annotated[TokenPayload, Depends(get_current_user)],
    scenario_name: str = Body(default="WEB_APP_COMPROMISE", embed=True),
):
    """Trigger an end-to-end controlled attack simulation inside the isolated cyber range."""
    simulator = AttackSimulatorService(session)
    result = await simulator.run_scenario(scenario_name=scenario_name)
    return result
