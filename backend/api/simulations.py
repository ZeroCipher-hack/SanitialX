"""Attack Simulator API Router for SanitialX."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_current_user, get_db_session
from core.security import TokenPayload
from db.repositories.simulation_repository import PostgresSimulationRepository
from simulation.scenarios import SCENARIOS
from simulation.simulator import AttackSimulatorService

router = APIRouter(prefix="/simulations", tags=["Attack Simulator"])


@router.get("/scenarios")
async def list_scenarios(
    _user: Annotated[TokenPayload, Depends(get_current_user)],
):
    """List scenarios available to the controlled Cyber Range."""
    return [
        {
            "name": scenario.name,
            "title": scenario.title,
            "description": scenario.description,
            "difficulty": scenario.difficulty,
        }
        for scenario in SCENARIOS.values()
    ]


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
    """Trigger an end-to-end controlled attack simulation."""
    try:
        return await AttackSimulatorService(session).run_scenario(scenario_name=scenario_name)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
