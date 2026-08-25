"""Integration tests for the fixed /auth/token endpoint.

Guards against regression of the credential-bypass vulnerability where any
username/password combination was accepted and the client could pick its
own role (including 'admin').
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from async_asgi_testclient import TestClient

from auth.models import User
from core.config import Settings
from core.container import ApplicationContainer
from core.security import hash_password
from db.base import Base
from db.session import DatabaseSessionManager
from main import app

# Settings() now requires real, non-placeholder secrets to boot (see
# core/config.py _reject_insecure_secrets). Tests must supply their own
# throwaway values — at least 32 chars, not in the known-placeholder set.
_TEST_JWT_SECRET = "test-only-jwt-secret-" + "x" * 20
_TEST_API_KEY = "test-only-api-key-" + "x" * 20


@pytest.fixture
async def client():
    settings = Settings(
        ENVIRONMENT="testing",
        DATABASE_URL="sqlite+aiosqlite:///:memory:",
        jwt_secret_key=_TEST_JWT_SECRET,
        api_key=_TEST_API_KEY,
        redis_url="redis://localhost:6380/0",  # matches docker-compose.test.yml redis-test
    )
    db_mgr = DatabaseSessionManager(settings.DATABASE_URL)
    db_mgr.init()
    async with db_mgr._engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    container = ApplicationContainer(settings=settings, db_manager=db_mgr)
    app.state.container = container
    app.state.is_ready = True

    # Seed one known user directly through the repository.
    await container.user_repository.create(
        User(
            user_id=str(uuid.uuid4()),
            username="analyst_jane",
            password_hash=hash_password("correct-horse-battery-staple"),
            role="analyst",
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
    )

    async with TestClient(app) as test_client:
        yield test_client

    # Clean up any rate-limit / revocation keys this test wrote, so test
    # runs don't bleed into each other via the shared test Redis instance.
    await container.redis_client.flushdb()
    await db_mgr.close()


class TestAuthTokenEndpoint:
    @pytest.mark.asyncio
    async def test_correct_credentials_issue_token_with_stored_role(self, client: TestClient) -> None:
        resp = await client.post(
            "/api/v1/auth/token",
            json={"username": "analyst_jane", "password": "correct-horse-battery-staple"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["role"] == "analyst"
        assert isinstance(body["access_token"], str) and body["access_token"]

    @pytest.mark.asyncio
    async def test_wrong_password_rejected(self, client: TestClient) -> None:
        resp = await client.post(
            "/api/v1/auth/token",
            json={"username": "analyst_jane", "password": "totally-wrong"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_unknown_username_rejected(self, client: TestClient) -> None:
        resp = await client.post(
            "/api/v1/auth/token",
            json={"username": "nobody", "password": "anything"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_client_cannot_self_escalate_role(self, client: TestClient) -> None:
        """The stored user is 'analyst' — extra client-supplied role claims,
        if sent, must never influence the issued token's role."""
        resp = await client.post(
            "/api/v1/auth/token",
            json={
                "username": "analyst_jane",
                "password": "correct-horse-battery-staple",
                "requested_role": "admin",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["role"] == "analyst"

    @pytest.mark.asyncio
    async def test_inactive_user_rejected(self, client: TestClient) -> None:
        container: ApplicationContainer = app.state.container
        await container.user_repository.create(
            User(
                user_id=str(uuid.uuid4()),
                username="disabled_user",
                password_hash=hash_password("some-password-123"),
                role="reader",
                is_active=False,
                created_at=datetime.now(timezone.utc),
            )
        )
        resp = await client.post(
            "/api/v1/auth/token",
            json={"username": "disabled_user", "password": "some-password-123"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_sixth_attempt_in_window_is_rate_limited(self, client: TestClient) -> None:
        for _ in range(5):
            await client.post(
                "/api/v1/auth/token",
                json={"username": "analyst_jane", "password": "wrong"},
            )
        resp = await client.post(
            "/api/v1/auth/token",
            json={"username": "analyst_jane", "password": "wrong"},
        )
        assert resp.status_code == 429

    @pytest.mark.asyncio
    async def test_logout_revokes_token(self, client: TestClient) -> None:
        login_resp = await client.post(
            "/api/v1/auth/token",
            json={"username": "analyst_jane", "password": "correct-horse-battery-staple"},
        )
        token = login_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        logout_resp = await client.post("/api/v1/auth/logout", headers=headers)
        assert logout_resp.status_code == 204

        # Token still has a valid signature and hasn't expired, but must be
        # rejected because it was revoked.
        protected_resp = await client.get("/api/v1/incidents", headers=headers)
        assert protected_resp.status_code == 401
