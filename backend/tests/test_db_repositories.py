"""Unit tests for Phase 10 DB repositories using sqlite+aiosqlite."""

from __future__ import annotations

from datetime import datetime, timezone
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from core.errors import IncidentConflictError
from correlation.enums import Severity
from db.base import Base
from db.repositories.incident_repository import PostgresIncidentRepository
from db.repositories.rule_repository import PostgresDetectionRuleRepository
from incidents.enums import IncidentStatus
from incidents.models import Incident


@pytest.fixture
async def async_session_factory():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    yield factory
    await engine.dispose()


def _make_incident(inc_id: str = "inc-100", version: int = 1) -> Incident:
    now = datetime.now(timezone.utc)
    return Incident(
        incident_id=inc_id,
        title="Test Incident",
        description="Test Description",
        severity=Severity.HIGH,
        status=IncidentStatus.OPEN,
        version=version,
        created_at=now,
        updated_at=now,
        source_ip="192.168.1.100",
        destination_ip="10.0.0.1",
        triggering_detection_ids=["det-1"],
        context={"test": "data"},
    )


class TestPostgresIncidentRepository:
    @pytest.mark.asyncio
    async def test_create_and_get_by_id(self, async_session_factory) -> None:
        repo = PostgresIncidentRepository(async_session_factory)
        inc = _make_incident("inc-1")

        created = await repo.create(inc)
        assert created.incident_id == "inc-1"
        assert created.version == 1

        fetched = await repo.get_by_id("inc-1")
        assert fetched is not None
        assert fetched.title == "Test Incident"
        assert fetched.status == IncidentStatus.OPEN

    @pytest.mark.asyncio
    async def test_update_optimistic_concurrency_success(self, async_session_factory) -> None:
        repo = PostgresIncidentRepository(async_session_factory)
        inc = await repo.create(_make_incident("inc-2", version=1))

        # Update with expected_version=1 -> version bumped to 2
        updated_input = Incident(
            incident_id=inc.incident_id,
            title="Updated Title",
            description=inc.description,
            severity=inc.severity,
            status=IncidentStatus.INVESTIGATING,
            version=2,
            created_at=inc.created_at,
            updated_at=datetime.now(timezone.utc),
            source_ip=inc.source_ip,
            destination_ip=inc.destination_ip,
        )

        result = await repo.update(updated_input, expected_version=1)
        assert result.version == 2
        assert result.status == IncidentStatus.INVESTIGATING
        assert result.title == "Updated Title"

    @pytest.mark.asyncio
    async def test_update_optimistic_concurrency_conflict_raises_error(self, async_session_factory) -> None:
        repo = PostgresIncidentRepository(async_session_factory)
        inc = await repo.create(_make_incident("inc-3", version=1))

        # First update succeeds, DB version becomes 2
        u1 = Incident(
            incident_id=inc.incident_id,
            title=inc.title,
            description=inc.description,
            severity=inc.severity,
            status=IncidentStatus.INVESTIGATING,
            version=2,
            created_at=inc.created_at,
            updated_at=datetime.now(timezone.utc),
        )
        await repo.update(u1, expected_version=1)

        # Stale update attempting with expected_version=1 must raise IncidentConflictError
        u_stale = Incident(
            incident_id=inc.incident_id,
            title="Stale Update",
            description=inc.description,
            severity=inc.severity,
            status=IncidentStatus.CLOSED,
            version=3,
            created_at=inc.created_at,
            updated_at=datetime.now(timezone.utc),
        )

        with pytest.raises(IncidentConflictError, match="Concurrency conflict"):
            await repo.update(u_stale, expected_version=1)

    @pytest.mark.asyncio
    async def test_list_all_pagination(self, async_session_factory) -> None:
        repo = PostgresIncidentRepository(async_session_factory)
        for i in range(5):
            await repo.create(_make_incident(f"inc-list-{i}"))

        page1 = await repo.list_all(limit=3, offset=0)
        assert len(page1) == 3

        page2 = await repo.list_all(limit=3, offset=3)
        assert len(page2) == 2


class TestPostgresDetectionRuleRepository:
    @pytest.mark.asyncio
    async def test_save_and_get_rule(self, async_session_factory) -> None:
        repo = PostgresDetectionRuleRepository(async_session_factory)

        await repo.save_rule(
            rule_id="R-1",
            rule_name="Rule 1",
            severity="HIGH",
            description="Desc 1",
            parameters={"threshold": 5},
        )

        rule = await repo.get_rule("R-1")
        assert rule is not None
        assert rule["rule_name"] == "Rule 1"
        assert rule["parameters"]["threshold"] == 5

        rules_list = await repo.list_rules()
        assert len(rules_list) == 1
