"""Integration coverage for approval-based SOAR -> endpoint command lifecycle."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from db.base import Base
from db.models.agent import AgentModel
from db.models.incident import IncidentORM
from db.repositories.soar_repository import PostgresSoarRepository


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as db:
        yield db
    await engine.dispose()


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


async def _seed_incident_and_agent(session: AsyncSession) -> tuple[IncidentORM, AgentModel]:
    incident = IncidentORM(
        incident_id="inc-soar-e2e", title="Suspicious endpoint activity", description="Integration test incident",
        severity="HIGH", status="OPEN", source_ip="10.0.0.50", destination_ip="10.0.0.10",
        triggering_detection_ids=[], context={},
    )
    agent = AgentModel(
        agent_id="linux-test-agent", hostname="endpoint.local", ip_address="10.0.0.10", os="Linux",
        status="ONLINE", lifecycle_status="MANAGED", agent_token_hash="a" * 64,
    )
    session.add_all([incident, agent]); await session.commit(); return incident, agent


async def _approved_action(session: AsyncSession, action_type: str = "COLLECT_FORENSICS"):
    incident, agent = await _seed_incident_and_agent(session)
    repo = PostgresSoarRepository(session)
    action = await repo.create_action({
        "incident_id": incident.incident_id,
        "action_type": action_type,
        "target_type": "ASSET",
        "target_value": agent.agent_id,
        "parameters": {},
        "risk_level": "LOW",
        "reason": "Read-only endpoint operation.",
    }, actor="analyst@example.local")
    action = await repo.decide(action, approve=True, actor="analyst@example.local")
    return repo, incident, agent, action


@pytest.mark.asyncio
async def test_approved_action_flows_through_agent_command_to_executed_audit(session: AsyncSession) -> None:
    repo, incident, agent, action = await _approved_action(session)
    command = await repo.queue_agent_command(action, agent_id=agent.agent_id, command_type="COLLECT_SYSTEM_INFO", payload={"incident_id":incident.incident_id}, actor="analyst@example.local")
    duplicate = await repo.queue_agent_command(action, agent_id=agent.agent_id, command_type="COLLECT_SYSTEM_INFO", payload={"incident_id":incident.incident_id}, actor="analyst@example.local")
    assert duplicate.command_id == command.command_id
    command = await repo.claim_agent_command(command)
    assert command.status == "CLAIMED"
    assert command.lease_until is not None
    assert command.attempt_count == 1
    command = await repo.complete_agent_command(command, result={"ok":True,"message":"System information collected.","data":{"hostname":agent.hostname}})
    assert command.status == "COMPLETED"
    assert command.lease_until is None
    refreshed_action = await repo.get(action.action_id)
    assert refreshed_action is not None and refreshed_action.status == "EXECUTED"
    audit = await repo.audit(action.action_id)
    assert [entry.event for entry in audit] == ["REQUESTED","APPROVED","COMMAND_QUEUED","COMPLETED"]
    assert audit[-1].details["attempt_count"] == 1


@pytest.mark.asyncio
async def test_stale_claim_is_redelivered_after_lease_expiry(session: AsyncSession) -> None:
    repo, incident, agent, action = await _approved_action(session)
    command = await repo.queue_agent_command(action, agent_id=agent.agent_id, command_type="COLLECT_SYSTEM_INFO", payload={"incident_id":incident.incident_id}, actor="analyst@example.local")
    command = await repo.claim_agent_command(command)
    assert command.attempt_count == 1
    assert await repo.pending_agent_commands(agent.agent_id) == []

    command.lease_until = datetime.now(timezone.utc) - timedelta(seconds=1)
    await session.commit()
    pending = await repo.pending_agent_commands(agent.agent_id)
    assert [item.command_id for item in pending] == [command.command_id]

    reclaimed = await repo.claim_agent_command(pending[0])
    assert reclaimed.status == "CLAIMED"
    assert reclaimed.attempt_count == 2
    assert reclaimed.lease_until is not None
    assert _utc(reclaimed.lease_until) > datetime.now(timezone.utc)


@pytest.mark.asyncio
async def test_failed_agent_result_marks_soar_action_failed(session: AsyncSession) -> None:
    repo, incident, agent, action = await _approved_action(session, "REQUEST_RESCAN")
    command = await repo.queue_agent_command(action, agent_id=agent.agent_id, command_type="REFRESH_INVENTORY", payload={"incident_id":incident.incident_id}, actor="analyst@example.local")
    command = await repo.claim_agent_command(command)
    await repo.complete_agent_command(command, result={"ok":False,"message":"Inventory collection failed.","data":{}})
    refreshed_action = await repo.get(action.action_id)
    assert refreshed_action is not None and refreshed_action.status == "FAILED"
    audit = await repo.audit(action.action_id)
    assert audit[-1].event == "FAILED"
