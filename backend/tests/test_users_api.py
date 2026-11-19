"""Tests for administrator user management and session invalidation."""

from __future__ import annotations

import pytest

from core.container import ApplicationContainer
from core.security import create_access_token, hash_password
from main import app
from tests.test_api import client  # noqa: F401  (shared fixture)


def _token(username: str, role: str) -> dict[str, str]:
    s = app.state.container.settings
    return {"Authorization": "Bearer " + create_access_token(subject=username, role=role, secret_key=s.jwt_secret_key, algorithm=s.jwt_algorithm)}


async def _seed_admin(name: str = "boss") -> dict:
    from datetime import datetime, timezone
    from auth.models import User
    container: ApplicationContainer = app.state.container
    user = await container.user_repository.create(User(user_id=f"id-{name}", username=name, password_hash=hash_password("Passw0rd!x"),
                                                        role="admin", is_active=True, created_at=datetime.now(timezone.utc)))
    return {"user_id": user.user_id, "username": name}


async def _create(client, name: str, role: str = "analyst", password: str = "Passw0rd!x") -> dict:
    r = await client.post("/api/v1/users", json={"username": name, "password": password, "role": role}, headers=_token("boss", "admin"))
    assert r.status_code == 201, r.text
    return r.json()


@pytest.mark.asyncio
async def test_admin_only_and_no_hash_leak(client) -> None:  # noqa: F811
    await _seed_admin()
    assert (await client.get("/api/v1/users", headers=_token("x", "analyst"))).status_code == 403
    assert (await client.post("/api/v1/users", json={"username": "abc", "password": "Passw0rd!x", "role": "reader"},
                              headers=_token("x", "analyst"))).status_code == 403
    listed = await client.get("/api/v1/users", headers=_token("boss", "admin"))
    assert listed.status_code == 200
    assert "password" not in listed.text and "hash" not in listed.text


@pytest.mark.asyncio
async def test_create_validates_and_rejects_duplicates(client) -> None:  # noqa: F811
    await _seed_admin()
    await _create(client, "ali")
    dup = await client.post("/api/v1/users", json={"username": "ali", "password": "Passw0rd!x", "role": "reader"}, headers=_token("boss", "admin"))
    assert dup.status_code == 409
    for bad in ({"username": "a", "password": "Passw0rd!x", "role": "reader"},
                {"username": "bad name!", "password": "Passw0rd!x", "role": "reader"},
                {"username": "okname", "password": "short", "role": "reader"},
                {"username": "okname", "password": "Passw0rd!x", "role": "root"}):
        assert (await client.post("/api/v1/users", json=bad, headers=_token("boss", "admin"))).status_code == 422


@pytest.mark.asyncio
async def test_created_user_can_login_and_deactivation_blocks_everything(client) -> None:  # noqa: F811
    await _seed_admin()
    ali = await _create(client, "ali")
    login = await client.post("/api/v1/auth/token", json={"username": "ali", "password": "Passw0rd!x"})
    assert login.status_code == 200
    ali_headers = {"Authorization": "Bearer " + login.json()["access_token"]}
    assert (await client.get("/api/v1/news", headers=ali_headers)).status_code == 200

    off = await client.patch(f"/api/v1/users/{ali['user_id']}", json={"is_active": False}, headers=_token("boss", "admin"))
    assert off.status_code == 200 and off.json()["is_active"] is False
    assert (await client.get("/api/v1/news", headers=ali_headers)).status_code == 401  # existing session killed
    assert (await client.post("/api/v1/auth/token", json={"username": "ali", "password": "Passw0rd!x"})).status_code == 401


@pytest.mark.asyncio
async def test_role_change_and_password_reset_invalidate_old_tokens(client) -> None:  # noqa: F811
    await _seed_admin()
    ali = await _create(client, "ali")
    old = {"Authorization": "Bearer " + (await client.post("/api/v1/auth/token", json={"username": "ali", "password": "Passw0rd!x"})).json()["access_token"]}

    assert (await client.patch(f"/api/v1/users/{ali['user_id']}", json={"role": "reader"}, headers=_token("boss", "admin"))).json()["role"] == "reader"
    assert (await client.get("/api/v1/news", headers=old)).status_code == 401

    reset = await client.post(f"/api/v1/users/{ali['user_id']}/password", json={"password": "N3wPassw0rd!"}, headers=_token("boss", "admin"))
    assert reset.status_code == 200
    assert (await client.post("/api/v1/auth/token", json={"username": "ali", "password": "Passw0rd!x"})).status_code == 401
    assert (await client.post("/api/v1/auth/token", json={"username": "ali", "password": "N3wPassw0rd!"})).status_code == 200


@pytest.mark.asyncio
async def test_cannot_lock_out_last_or_own_admin(client) -> None:  # noqa: F811
    boss = await _seed_admin()
    own = await client.patch(f"/api/v1/users/{boss['user_id']}", json={"is_active": False}, headers=_token("boss", "admin"))
    assert own.status_code == 409
    assert (await client.patch(f"/api/v1/users/{boss['user_id']}", json={"role": "analyst"}, headers=_token("boss", "admin"))).status_code == 409

    second = await _create(client, "second", role="admin")
    # a different admin may not remove the only OTHER admin once only two remain active? two admins -> allowed to demote one
    assert (await client.patch(f"/api/v1/users/{second['user_id']}", json={"role": "analyst"}, headers=_token("boss", "admin"))).status_code == 200
    # now boss is last admin: another (spoofed) admin token cannot demote them
    assert (await client.patch(f"/api/v1/users/{boss['user_id']}", json={"role": "reader"}, headers=_token("ghost", "admin"))).status_code == 409
    assert (await client.patch("/api/v1/users/nope", json={"role": "reader"}, headers=_token("boss", "admin"))).status_code == 404
