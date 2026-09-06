"""Regression tests for endpoint software inventory replacement."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from db.base import Base
from db.models.agent import AgentModel
from db.repositories.vulnerability_repository import PostgresVulnerabilityRepository


@pytest.fixture
async def inventory_session() -> AsyncSession:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        session.add(
            AgentModel(
                agent_id="linux-test-agent",
                hostname="kali-test",
                ip_address="127.0.0.1",
                os="Kali Linux",
            )
        )
        await session.commit()
        yield session

    await engine.dispose()


@pytest.mark.asyncio
async def test_replace_inventory_deduplicates_same_software_identity(inventory_session: AsyncSession) -> None:
    repo = PostgresVulnerabilityRepository(inventory_session)
    software = [
        {
            "vendor": "debian",
            "product": "libcolord2",
            "version": "1.4.8-3",
            "package_name": "libcolord2",
            "ecosystem": "deb",
            "source": "sanitialx-linux-agent",
        },
        {
            "vendor": "debian",
            "product": "libcolord2",
            "version": "1.4.8-3",
            "package_name": "libcolord2",
            "ecosystem": "deb",
            "purl": "pkg:deb/debian/libcolord2@1.4.8-3",
            "source": "sanitialx-linux-agent",
        },
    ]

    stored = await repo.replace_software_inventory("linux-test-agent", software)

    assert len(stored) == 1
    assert stored[0].product == "libcolord2"
    assert stored[0].purl == "pkg:deb/debian/libcolord2@1.4.8-3"


@pytest.mark.asyncio
async def test_replace_inventory_is_idempotent_across_repeated_uploads(inventory_session: AsyncSession) -> None:
    repo = PostgresVulnerabilityRepository(inventory_session)
    software = [
        {
            "vendor": "debian",
            "product": "gcc-15-base",
            "version": "15.3.0-1",
            "package_name": "gcc-15-base",
            "ecosystem": "deb",
            "source": "sanitialx-linux-agent",
        },
        {
            "vendor": "debian",
            "product": "libcolord2",
            "version": "1.4.8-3",
            "package_name": "libcolord2",
            "ecosystem": "deb",
            "source": "sanitialx-linux-agent",
        },
    ]

    first = await repo.replace_software_inventory("linux-test-agent", software)
    second = await repo.replace_software_inventory("linux-test-agent", software)
    inventory = await repo.list_software_inventory("linux-test-agent")

    assert len(first) == 2
    assert len(second) == 2
    assert len(inventory) == 2
    assert {(item.product, item.version) for item in inventory} == {
        ("gcc-15-base", "15.3.0-1"),
        ("libcolord2", "1.4.8-3"),
    }
