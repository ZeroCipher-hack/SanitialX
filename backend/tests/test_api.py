"""Unit and integration tests for Phase 14/15 APIs with JWT Auth."""

from __future__ import annotations

from datetime import datetime, timezone
import pytest
import fakeredis.aioredis
from async_asgi_testclient import TestClient

from core.config import Settings
from core.container import ApplicationContainer
from core.security import create_access_token
from db.base import Base
from db.session import DatabaseSessionManager
from main import app


@pytest.fixture
async def client():
    settings = Settings(
        ENVIRONMENT="testing",
        DATABASE_URL="sqlite+aiosqlite:///:memory:",
        jwt_secret_key="test-only-jwt-secret-" + "x" * 20,
        api_key="test-only-api-key-" + "x" * 20,
        redis_url="redis://localhost:6379/0",
    )
    db_mgr = DatabaseSessionManager(settings.DATABASE_URL)
    db_mgr.init()
    async with db_mgr._engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    container = ApplicationContainer(settings=settings, db_manager=db_mgr)
    container.redis_client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    app.state.container = container
    app.state.is_ready = True

    async with TestClient(app) as test_client:
        yield test_client

    await container.redis_client.aclose()
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
        assert response.json()["status"] == "ready"


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

        headers = _get_auth_headers("analyst")
        res1 = await client.patch(
            "/api/v1/incidents/inc-api-1/status",
            json={"status": "INVESTIGATING"},
            headers=headers,
        )
        assert res1.status_code == 200
        assert res1.json()["status"] == "INVESTIGATING"
        assert res1.json()["version"] == 2


class TestRulesAPI:
    @pytest.mark.asyncio
    async def test_put_and_get_rule(self, client: TestClient) -> None:
        headers = _get_auth_headers("admin")
        payload = {
            "rule_name": "Custom PortScan",
            "severity": "CRITICAL",
            "description": "Scans N ports",
            "enabled": True,
            "parameters": {
                "schema_version": 1,
                "rule_type": "distinct_threshold",
                "conditions": [],
                "group_by": "source_ip",
                "threshold": 10,
                "window_seconds": 60,
                "cooldown_seconds": 180,
                "distinct_by": "destination_port",
                "mitre": {
                    "tactic": "Discovery",
                    "technique_id": "T1046",
                    "technique": "Network Service Discovery",
                },
            },
        }
        put_res = await client.put("/api/v1/rules/R-TEST-1", json=payload, headers=headers)
        assert put_res.status_code == 200
        data = put_res.json()
        assert data["rule_id"] == "R-TEST-1"
        assert data["severity"] == "CRITICAL"
        assert data["version"] == 1
        assert data["parameters"]["schema_version"] == 1

        get_res = await client.get("/api/v1/rules/R-TEST-1", headers=headers)
        assert get_res.status_code == 200
        assert get_res.json()["rule_name"] == "Custom PortScan"

        update_res = await client.put(
            "/api/v1/rules/R-TEST-1",
            json={"enabled": False, "expected_version": 1},
            headers=headers,
        )
        assert update_res.status_code == 200
        assert update_res.json()["version"] == 2
        assert update_res.json()["enabled"] is False

        stale_res = await client.put(
            "/api/v1/rules/R-TEST-1",
            json={"enabled": True, "expected_version": 1},
            headers=headers,
        )
        assert stale_res.status_code == 409


class TestAssetsAPI:
    async def _seed_asset(self) -> None:
        container: ApplicationContainer = app.state.container
        async with container.db_manager.sessionmaker() as session:
            from db.repositories.agent_repository import PostgresAgentRepository

            await PostgresAgentRepository(session).upsert_agent(
                {
                    "agent_id": "asset-1",
                    "hostname": "prod-web-01",
                    "ip_address": "10.0.0.10",
                    "os": "Ubuntu 24.04",
                    "status": "ONLINE",
                    "risk_score": 72,
                }
            )

    @pytest.mark.asyncio
    async def test_asset_metadata_update_and_filters(self, client: TestClient) -> None:
        await self._seed_asset()
        headers = _get_auth_headers("analyst")

        patch = await client.patch(
            "/api/v1/agents/asset-1",
            json={
                "asset_type": "SERVER",
                "criticality": "CRITICAL",
                "environment": "PRODUCTION",
                "owner": "Platform Team",
                "internet_exposed": True,
                "tags": [" Web ", "Production", "web"],
            },
            headers=headers,
        )
        assert patch.status_code == 200
        data = patch.json()
        assert data["asset_type"] == "SERVER"
        assert data["criticality"] == "CRITICAL"
        assert data["internet_exposed"] is True
        assert data["tags"] == ["web", "production"]

        listing = await client.get(
            "/api/v1/agents?asset_type=SERVER&criticality=CRITICAL&internet_exposed=true&q=prod-web",
            headers=headers,
        )
        assert listing.status_code == 200
        assert len(listing.json()) == 1
        assert listing.json()[0]["agent_id"] == "asset-1"

    @pytest.mark.asyncio
    async def test_asset_detail_includes_exposure_summary(self, client: TestClient) -> None:
        await self._seed_asset()
        headers = _get_auth_headers("reader")
        detail = await client.get("/api/v1/agents/asset-1", headers=headers)
        assert detail.status_code == 200
        data = detail.json()
        assert data["hostname"] == "prod-web-01"
        assert data["software_count"] == 0
        assert data["exposure_summary"] == {
            "total": 0,
            "affected": 0,
            "critical": 0,
            "high": 0,
            "max_risk_score": 0,
        }

    @pytest.mark.asyncio
    async def test_reader_cannot_change_asset_metadata(self, client: TestClient) -> None:
        await self._seed_asset()
        response = await client.patch(
            "/api/v1/agents/asset-1",
            json={"criticality": "HIGH"},
            headers=_get_auth_headers("reader"),
        )
        assert response.status_code == 403
