"""Unit and integration tests for Phase 14/15 APIs with JWT Auth."""

from __future__ import annotations

from datetime import datetime, timezone
import pytest
from async_asgi_testclient import TestClient

from core.config import Settings
from core.container import ApplicationContainer
from core.security import create_access_token
from db.base import Base
from db.repositories.incident_repository import PostgresIncidentRepository
from db.repositories.rule_repository import PostgresDetectionRuleRepository
from db.session import DatabaseSessionManager
from main import app


@pytest.fixture
async def client():
    # Use SQLite in-memory for testing API endpoints against database
    settings = Settings(
        ENVIRONMENT="testing",
        DATABASE_URL="sqlite+aiosqlite:///:memory:",
        jwt_secret_key="test-only-jwt-secret-" + "x" * 20,
        api_key="test-only-api-key-" + "x" * 20,
        redis_url="redis://localhost:6380/0",
    )
    db_mgr = DatabaseSessionManager(settings.DATABASE_URL)
    db_mgr.init()
    async with db_mgr._engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    container = ApplicationContainer(settings=settings, db_manager=db_mgr)
    app.state.container = container
    app.state.is_ready = True

    async with TestClient(app) as test_client:
        yield test_client

    await db_mgr.close()


def _get_auth_headers(role: str = "analyst") -> dict[str, str]:
    container: ApplicationContainer = app.state.container
    token = create_access_token(
        subject="test-user",
        role=role,
        secret_key=container.settings.jwt_secret_key,
        algorithm=container.settings.jwt_algorithm,
    )
    return {"Authorization": f"Bearer {token}"}


class TestHealthAPI:
    @pytest.mark.asyncio
    async def test_liveness_endpoint_unauthenticated(self, client: TestClient) -> None:
        response = await client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["is_ready"] is True

    @pytest.mark.asyncio
    async def test_readiness_endpoint_unauthorized_without_token(self, client: TestClient) -> None:
        response = await client.get("/api/v1/health/ready")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_readiness_endpoint_authenticated(self, client: TestClient) -> None:
        headers = _get_auth_headers("reader")
        response = await client.get("/api/v1/health/ready", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ready"


class TestIncidentsAPI:
    @pytest.mark.asyncio
    async def test_list_incidents_empty_authenticated(self, client: TestClient) -> None:
        headers = _get_auth_headers("reader")
        response = await client.get("/api/v1/incidents", headers=headers)
        assert response.status_code == 200
        assert response.json() == []

    @pytest.mark.asyncio
    async def test_patch_incident_status_unauthorized_missing_token(self, client: TestClient) -> None:
        response = await client.patch("/api/v1/incidents/inc-1/status", json={"status": "INVESTIGATING"})
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_patch_incident_status_forbidden_reader_role(self, client: TestClient) -> None:
        headers = _get_auth_headers("reader")
        response = await client.patch(
            "/api/v1/incidents/inc-1/status",
            json={"status": "INVESTIGATING"},
            headers=headers,
        )
        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_patch_incident_status_success_analyst_role(self, client: TestClient) -> None:
        container: ApplicationContainer = app.state.container

        # Seed an incident into repo
        from correlation.enums import Severity
        from incidents.enums import IncidentStatus
        from incidents.models import Incident

        inc = Incident(
            incident_id="inc-api-1",
            title="API Test Incident",
            description="Desc",
            severity=Severity.MEDIUM,
            status=IncidentStatus.OPEN,
            version=1,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        await container.incident_repository.create(inc)

        # Authorized status transition: OPEN -> INVESTIGATING with analyst role
        headers = _get_auth_headers("analyst")
        res1 = await client.patch(
            "/api/v1/incidents/inc-api-1/status",
            json={"status": "INVESTIGATING"},
            headers=headers,
        )
        assert res1.status_code == 200
        data = res1.json()
        assert data["status"] == "INVESTIGATING"
        assert data["version"] == 2


class TestRulesAPI:
    @pytest.mark.asyncio
    async def test_put_and_get_rule(self, client: TestClient) -> None:
        headers = _get_auth_headers("admin")

        payload = {
            "rule_name": "Custom PortScan",
            "severity": "CRITICAL",
            "description": "Scans N ports",
            "enabled": True,
            "parameters": {"threshold": 10},
        }

        put_res = await client.put("/api/v1/rules/R-TEST-1", json=payload, headers=headers)
        assert put_res.status_code == 200
        data = put_res.json()
        assert data["rule_id"] == "R-TEST-1"
        assert data["severity"] == "CRITICAL"

        get_res = await client.get("/api/v1/rules/R-TEST-1", headers=headers)
        assert get_res.status_code == 200
        assert get_res.json()["rule_name"] == "Custom PortScan"
