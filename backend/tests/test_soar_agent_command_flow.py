"""Integration coverage for approval-based SOAR -> endpoint command lifecycle."""
from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from db.base import Base
from db.models.agent import AgentModel
from db.models.incident import IncidentORM
from db.models.soar import AgentCommandModel, SoarActionModel, SoarAuditModel
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


async def _seed_incident_and_agent(session: AsyncSession) -> tuple[IncidentORM, AgentModel]:
    incident = IncidentORM(
        incident_id="inc-soar-e2e",
        title="Suspicious endpoint activity",
        description="Integration test incident",
        severity="HIGH",
        status="OPEN",
        source_ip="10.0.0.50",
        destination_ip="10.0.0.10",
        triggering_detection_ids=[],
        context={},
    )
    agent = AgentModel(
        agent_id="linux-test-agent",
        hostname="endpoint.local",
        ip_address="10.0.0.10",
        os="Linux",
        status="ONLINE",
        lifecycle_status="MANAGED",
        agent_token_hash="a" * 64,
    )
    session.add_all([incident, agent])
    await session.commit()
    return incident, agent


@pytest.mark.asyncio
async def test_approved_action_flows_through_agent_command_to_executed_audit(session: AsyncSession) -> None:
    incident, agent = await _seed_incident_and_agent(session)
    repo = PostgresSoarRepository(session)

    action = await repo.create_action(
        {
            "incident_id": incident.incident_id,
            "action_type": "COLLECT_FORENSICS",
            "target_type": "ASSET",
            "target_value": agent.agent_id,
            "parameters": {},
            "risk_level": "LOW",
            "reason": "Collect read-only system information.",
        },
        actor="analyst@example.local",
    )
    assert action.status == "PENDING"

    with pytest.raises(ValueError, match="APPROVED"):
        await repo.queue_agent_command(
            action,
            agent_id=agent.agent_id,
            command_type="COLLECT_SYSTEM_INFO",
            payload={"incident_id": incident.incident_id},
            actor="analyst@example.local",
        )

    action = await repo.decide(action, approve=True, actor="analyst@example.local", note="Approved for read-only collection")
    assert action.status == "APPROVED"

    command = await repo.queue_agent_command(
        action,
        agent_id=agent.agent_id,
        command_type="COLLECT_SYSTEM_INFO",
        payload={"incident_id": incident.incident_id},
        actor="analyst@example.local",
    )
    assert command.status == "QUEUED"

    duplicate = await repo.queue_agent_command(
        action,
        agent_id=agent.agent_id,
        command_type="COLLECT_SYSTEM_INFO",
        payload={"incident_id": incident.incident_id},
        actor="analyst@example.local",
    )
    assert duplicate.command_id == command.command_id

    pending = await repo.pending_agent_commands(agent.agent_id)
    assert [item.command_id for item in pending] == [command.command_id]

    command = await repo.claim_agent_command(command)
    assert command.status == "CLAIMED"
    assert command.claimed_at is not None

    command = await repo.complete_agent_command(
        command,
        result={
            "ok": True,
            "message": "System information collected.",
            "data": {"hostname": agent.hostname, "platform": "Linux"},
        },
    )
    assert command.status == "COMPLETED"
    assert command.completed_at is not None

    refreshed_action = await repo.get(action.action_id)
    assert refreshed_action is not None
    assert refreshed_action.status == "EXECUTED"
    assert refreshed_action.execution_result["ok"] is True
    assert refreshed_action.execution_result["data"]["hostname"] == agent.hostname

    audit = await repo.audit(action.action_id)
    assert [entry.event for entry in audit] == ["REQUESTED", "APPROVED", "COMMAND_QUEUED", "COMPLETED"]
    assert audit[-1].actor == f"agent:{agent.agent_id}"


@pytest.mark.asyncio
async def test_failed_agent_result_marks_soar_action_failed(session: AsyncSession) -> None:
    incident, agent = await _seed_incident_and_agent(session)
    repo = PostgresSoarRepository(session)
    action = await repo.create_action(
        {
            "incident_id": incident.incident_id,
            "action_type": "REQUEST_RESCAN",
            "target_type": "ASSET",
            "target_value": agent.agent_id,
            "parameters": {},
            "risk_level": "LOW",
            "reason": "Refresh inventory.",
        },
        actor="analyst@example.local",
    )
    action = await repo.decide(action, approve=True, actor="analyst@example.local")
    command = await repo.queue_agent_command(
        action,
        agent_id=agent.agent_id,
        command_type="REFRESH_INVENTORY",
        payload={"incident_id": incident.incident_id},
        actor="analyst@example.local",
    )
    command = await repo.claim_agent_command(command)
    await repo.complete_agent_command(command, result={"ok": False, "message": "Inventory collection failed.", "data": {}})

    refreshed_action = await repo.get(action.action_id)
    assert refreshed_action is not None
    assert refreshed_action.status == "FAILED"
    assert refreshed_action.execution_result["ok"] is False
    audit = await repo.audit(action.action_id)
    assert audit[-1].event == "FAILED"
