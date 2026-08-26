"""
Unit and integration tests for SanitialX flagship modules (Simulator, Honeypots, Events, Agents, Attack Graph, Reports).
"""

import pytest
import uuid
from datetime import datetime, timezone
from httpx import ASGITransport, AsyncClient
from main import app
from core.config import Settings
from core.security import create_access_token, hash_password
from db.session import DatabaseSessionManager
from db.base import Base
from core.container import ApplicationContainer
from auth.models import User

_TEST_JWT_SECRET = "super-secret-key-for-jwt-signing-minimum-32-bytes!!"


@pytest.fixture
async def authenticated_client():
    settings = Settings(
        ENVIRONMENT="testing",
        DATABASE_URL="sqlite+aiosqlite:///:memory:",
        jwt_secret_key=_TEST_JWT_SECRET,
        redis_url="fakeredis://",
    )
    db_mgr = DatabaseSessionManager(settings.DATABASE_URL)
    db_mgr.init()
    async with db_mgr._engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    container = ApplicationContainer(settings=settings, db_manager=db_mgr)
    app.state.container = container
    app.state.is_ready = True

    token = create_access_token(
        subject="analyst_test",
        role="analyst",
        secret_key=_TEST_JWT_SECRET,
    )

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Authorization": f"Bearer {token}"},
    ) as ac:
        yield ac

    await db_mgr.close()


@pytest.mark.asyncio
async def test_events_endpoint(authenticated_client):
    res = await authenticated_client.get("/api/v1/events")
    assert res.status_code == 200
    assert isinstance(res.json(), list)


@pytest.mark.asyncio
async def test_agents_endpoint(authenticated_client):
    res = await authenticated_client.get("/api/v1/agents")
    assert res.status_code == 200
    assert isinstance(res.json(), list)


@pytest.mark.asyncio
async def test_honeypots_endpoint(authenticated_client):
    res = await authenticated_client.get("/api/v1/honeypots")
    assert res.status_code == 200
    assert isinstance(res.json(), list)


@pytest.mark.asyncio
async def test_simulation_run_endpoint(authenticated_client):
    # Run attack simulation
    sim_res = await authenticated_client.post("/api/v1/simulations/run", json={"scenario_name": "WEB_APP_COMPROMISE"})
    assert sim_res.status_code == 200
    data = sim_res.json()
    assert data["scenario_name"] == "WEB_APP_COMPROMISE"
    assert data["status"] == "COMPLETED"
    assert data["events_generated"] > 0
    assert data["generated_incident_id"] is not None

    # Fetch attack graph for the generated incident
    inc_id = data["generated_incident_id"]
    graph_res = await authenticated_client.get(f"/api/v1/attack-graph/{inc_id}")
    assert graph_res.status_code == 200
    assert len(graph_res.json()["nodes"]) > 0

    # Fetch report detail for the generated incident
    rep_res = await authenticated_client.get(f"/api/v1/reports/{inc_id}")
    assert rep_res.status_code == 200
    assert rep_res.json()["incident_id"] == inc_id
    assert len(rep_res.json()["recommended_actions"]) > 0
