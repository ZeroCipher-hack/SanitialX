"""Built-in detection rules are persisted once so the Rules page is never empty on a fresh install."""

from __future__ import annotations

import pytest

from core.config import Settings
from core.container import ApplicationContainer
from db.base import Base
from db.session import DatabaseSessionManager


@pytest.fixture
async def container():
    settings = Settings(
        ENVIRONMENT="testing",
        DATABASE_URL="sqlite+aiosqlite:///:memory:",
        jwt_secret_key="test-only-jwt-secret-" + "x" * 20,
        api_key="test-only-api-key-" + "x" * 20,
    )
    db = DatabaseSessionManager(settings.DATABASE_URL)
    db.init()
    async with db._engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield ApplicationContainer(settings=settings, db_manager=db)
    await db.close()


@pytest.mark.asyncio
async def test_seed_lists_all_builtin_rules_once(container: ApplicationContainer) -> None:
    expected = {r.rule_id for r in container.correlation_engine.rules}
    assert await container.seed_builtin_rules() == len(expected) >= 6
    stored = await container.rule_repository.list_rules(limit=100, offset=0)
    assert {r["rule_id"] for r in stored} == expected
    assert all(r["enabled"] and r["severity"] for r in stored)
    assert await container.seed_builtin_rules() == 0  # idempotent


@pytest.mark.asyncio
async def test_seed_keeps_operator_changes_and_disable_removes_rule(container: ApplicationContainer) -> None:
    await container.seed_builtin_rules()
    rule_id = "RULE-RDP-BRUTEFORCE-01"
    row = await container.rule_repository.get_rule(rule_id)
    await container.rule_repository.save_rule(
        rule_id=rule_id, rule_name=row["rule_name"], severity=row["severity"], enabled=False, expected_version=row["version"]
    )
    assert await container.seed_builtin_rules() == 0
    assert (await container.rule_repository.get_rule(rule_id))["enabled"] is False
    await container.refresh_detection_rules()
    assert rule_id not in {r.rule_id for r in container.correlation_engine.rules}
