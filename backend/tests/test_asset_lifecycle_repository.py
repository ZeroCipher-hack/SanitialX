"""Integration coverage for asset lifecycle and inventory freshness."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from db.base import Base
from db.models.agent import AgentModel
from db.repositories.agent_repository import PostgresAgentRepository


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as db:
        yield db
    await engine.dispose()


def _asset(agent_id: str, **overrides) -> AgentModel:
    values = {
        "agent_id": agent_id,
        "hostname": f"{agent_id}.local",
        "ip_address": "10.0.0.10",
        "os": "Linux",
        "status": "ONLINE",
        "lifecycle_status": "DISCOVERED",
        "criticality": "MEDIUM",
        "environment": "UNKNOWN",
        "internet_exposed": False,
        "risk_score": 0,
    }
    values.update(overrides)
    return AgentModel(**values)


@pytest.mark.asyncio
async def test_touch_inventory_promotes_discovered_asset_to_managed(session: AsyncSession) -> None:
    asset = _asset("asset-1")
    session.add(asset)
    await session.commit()

    repo = PostgresAgentRepository(session)
    updated = await repo.touch_inventory("asset-1")

    assert updated is not None
    assert updated["lifecycle_status"] == "MANAGED"
    assert updated["inventory_updated_at"] is not None


@pytest.mark.asyncio
async def test_touch_inventory_preserves_explicit_retired_state(session: AsyncSession) -> None:
    asset = _asset("asset-2", lifecycle_status="RETIRED")
    session.add(asset)
    await session.commit()

    repo = PostgresAgentRepository(session)
    updated = await repo.touch_inventory("asset-2")

    assert updated is not None
    assert updated["lifecycle_status"] == "RETIRED"
    assert updated["inventory_updated_at"] is not None


@pytest.mark.asyncio
async def test_lifecycle_filter_returns_only_requested_assets(session: AsyncSession) -> None:
    session.add_all(
        [
            _asset("asset-managed", lifecycle_status="MANAGED"),
            _asset("asset-retired", lifecycle_status="RETIRED", ip_address="10.0.0.11"),
        ]
    )
    await session.commit()

    repo = PostgresAgentRepository(session)
    items = await repo.list_agents(lifecycle_status="managed")

    assert [item["agent_id"] for item in items] == ["asset-managed"]


@pytest.mark.asyncio
async def test_inventory_summary_counts_managed_retired_and_stale(session: AsyncSession) -> None:
    now = datetime.now(timezone.utc)
    session.add_all(
        [
            _asset(
                "fresh-managed",
                lifecycle_status="MANAGED",
                inventory_updated_at=now - timedelta(hours=1),
                criticality="CRITICAL",
                environment="PRODUCTION",
                internet_exposed=True,
                risk_score=80,
            ),
            _asset(
                "stale-managed",
                lifecycle_status="MANAGED",
                inventory_updated_at=now - timedelta(hours=48),
                ip_address="10.0.0.12",
            ),
            _asset(
                "never-inventoried",
                lifecycle_status="DISCOVERED",
                inventory_updated_at=None,
                ip_address="10.0.0.13",
                status="OFFLINE",
            ),
            _asset(
                "retired",
                lifecycle_status="RETIRED",
                inventory_updated_at=now,
                ip_address="10.0.0.14",
            ),
        ]
    )
    await session.commit()

    summary = await PostgresAgentRepository(session).get_inventory_summary(stale_after_hours=24)

    assert summary["total_assets"] == 4
    assert summary["managed_assets"] == 2
    assert summary["retired_assets"] == 1
    assert summary["stale_inventory_assets"] == 2
    assert summary["critical_assets"] == 1
    assert summary["internet_facing_assets"] == 1
    assert summary["offline_assets"] == 1
    assert summary["high_risk_assets"] == 1
    assert summary["production_assets"] == 1
