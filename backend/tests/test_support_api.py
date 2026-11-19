"""Tests for support tickets and vendor news endpoints."""

from __future__ import annotations

import pytest
from async_asgi_testclient import TestClient

from core.container import ApplicationContainer
from core.security import create_access_token
from main import app
from tests.test_api import client  # noqa: F401  (shared fixture)


def _headers(user: str, role: str) -> dict[str, str]:
    container: ApplicationContainer = app.state.container
    token = create_access_token(
        subject=user,
        role=role,
        secret_key=container.settings.jwt_secret_key,
        algorithm=container.settings.jwt_algorithm,
    )
    return {"Authorization": f"Bearer {token}"}


TICKET = {"category": "BUG", "subject": "Dashboard slow", "message": "Loads in 20s"}


@pytest.mark.asyncio
async def test_ticket_lifecycle(client: TestClient) -> None:
    created = await client.post("/api/v1/support/tickets", json=TICKET, headers=_headers("ali", "analyst"))
    assert created.status_code == 201
    tid = created.json()["id"]
    assert created.json()["status"] == "OPEN"

    replied = await client.post(
        f"/api/v1/support/tickets/{tid}/reply", json={"reply": "Fixed in 1.2"}, headers=_headers("boss", "admin")
    )
    assert replied.status_code == 200
    assert replied.json()["status"] == "ANSWERED"

    closed = await client.post(f"/api/v1/support/tickets/{tid}/close", headers=_headers("ali", "analyst"))
    assert closed.json()["status"] == "CLOSED"


@pytest.mark.asyncio
async def test_non_admin_sees_only_own_tickets(client: TestClient) -> None:
    await client.post("/api/v1/support/tickets", json=TICKET, headers=_headers("ali", "analyst"))
    await client.post("/api/v1/support/tickets", json=TICKET, headers=_headers("vali", "analyst"))

    mine = await client.get("/api/v1/support/tickets", headers=_headers("ali", "analyst"))
    assert [t["created_by"] for t in mine.json()] == ["ali"]
    everyone = await client.get("/api/v1/support/tickets", headers=_headers("boss", "admin"))
    assert len(everyone.json()) == 2


@pytest.mark.asyncio
async def test_reply_close_and_export_permissions(client: TestClient) -> None:
    created = await client.post("/api/v1/support/tickets", json=TICKET, headers=_headers("ali", "analyst"))
    tid = created.json()["id"]

    denied = await client.post(
        f"/api/v1/support/tickets/{tid}/reply", json={"reply": "x"}, headers=_headers("ali", "analyst")
    )
    assert denied.status_code == 403
    other = await client.post(f"/api/v1/support/tickets/{tid}/close", headers=_headers("vali", "analyst"))
    assert other.status_code == 403
    assert (await client.get("/api/v1/support/export", headers=_headers("ali", "analyst"))).status_code == 403

    export = await client.get("/api/v1/support/export", headers=_headers("boss", "admin"))
    assert export.status_code == 200
    assert export.json()["tickets"][0]["subject"] == "Dashboard slow"
    assert "created_by" not in export.json()["tickets"][0]


@pytest.mark.asyncio
async def test_news_publish_admin_only_and_listed(client: TestClient) -> None:
    item = {"category": "RELEASE", "title": "v1.2 released", "body": "New rules", "version": "1.2.0"}
    assert (await client.post("/api/v1/news", json=item, headers=_headers("ali", "analyst"))).status_code == 403
    assert (await client.post("/api/v1/news", json=item, headers=_headers("boss", "admin"))).status_code == 201

    listed = await client.get("/api/v1/news", headers=_headers("ali", "analyst"))
    assert [n["title"] for n in listed.json()] == ["v1.2 released"]


@pytest.mark.asyncio
async def test_ticket_validation_and_missing(client: TestClient) -> None:
    bad = await client.post(
        "/api/v1/support/tickets", json={"category": "OTHER", "subject": "x", "message": "y"}, headers=_headers("ali", "analyst")
    )
    assert bad.status_code == 422
    missing = await client.post("/api/v1/support/tickets/999/close", headers=_headers("boss", "admin"))
    assert missing.status_code == 404
