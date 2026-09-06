"""Repository for approval-based SOAR actions, endpoint commands, and audit events."""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
import uuid
from sqlalchemy import desc, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from db.models.soar import AgentCommandModel, SoarActionModel, SoarAuditModel

COMMAND_LEASE_SECONDS = 120

class PostgresSoarRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create_action(self, data: dict, actor: str) -> SoarActionModel:
        action = SoarActionModel(action_id=str(uuid.uuid4()), requested_by=actor, **data)
        self._session.add(action)
        self._session.add(SoarAuditModel(audit_id=str(uuid.uuid4()), action_id=action.action_id, actor=actor, event="REQUESTED", details={"status":"PENDING"}))
        await self._session.commit(); await self._session.refresh(action); return action

    async def get(self, action_id: str) -> SoarActionModel | None:
        return await self._session.get(SoarActionModel, action_id)

    async def list(self, *, incident_id: str | None = None, status: str | None = None, limit: int = 100) -> list[SoarActionModel]:
        stmt = select(SoarActionModel)
        if incident_id: stmt = stmt.where(SoarActionModel.incident_id == incident_id)
        if status: stmt = stmt.where(SoarActionModel.status == status)
        result = await self._session.execute(stmt.order_by(desc(SoarActionModel.created_at)).limit(limit))
        return list(result.scalars().all())

    async def decide(self, action: SoarActionModel, *, approve: bool, actor: str, note: str = "") -> SoarActionModel:
        if action.status != "PENDING": raise ValueError("Only PENDING actions may be decided.")
        now = datetime.now(timezone.utc)
        action.status = "APPROVED" if approve else "REJECTED"
        action.decided_at = now
        action.version += 1
        if approve: action.approved_by = actor
        else: action.rejected_by = actor
        self._session.add(SoarAuditModel(audit_id=str(uuid.uuid4()), action_id=action.action_id, actor=actor, event=action.status, details={"note":note}))
        await self._session.commit(); await self._session.refresh(action); return action

    async def queue_agent_command(self, action: SoarActionModel, *, agent_id: str, command_type: str, payload: dict, actor: str) -> AgentCommandModel:
        if action.status != "APPROVED": raise ValueError("Action must be APPROVED before a command can be queued.")
        existing = await self._session.scalar(select(AgentCommandModel).where(AgentCommandModel.action_id == action.action_id).limit(1))
        if existing is not None: return existing
        command = AgentCommandModel(command_id=str(uuid.uuid4()), agent_id=agent_id, action_id=action.action_id, command_type=command_type, payload=payload, status="QUEUED", result={}, attempt_count=0)
        self._session.add(command)
        self._session.add(SoarAuditModel(audit_id=str(uuid.uuid4()), action_id=action.action_id, actor=actor, event="COMMAND_QUEUED", details={"command_id":command.command_id,"agent_id":agent_id,"command_type":command_type}))
        await self._session.commit(); await self._session.refresh(command); return command

    async def pending_agent_commands(self, agent_id: str, *, limit: int = 20) -> list[AgentCommandModel]:
        now = datetime.now(timezone.utc)
        result = await self._session.execute(
            select(AgentCommandModel)
            .where(
                AgentCommandModel.agent_id == agent_id,
                or_(
                    AgentCommandModel.status == "QUEUED",
                    (AgentCommandModel.status == "CLAIMED") & (AgentCommandModel.lease_until.is_not(None)) & (AgentCommandModel.lease_until <= now),
                ),
            )
            .order_by(AgentCommandModel.created_at)
            .limit(limit)
        )
        return list(result.scalars().all())

    async def claim_agent_command(self, command: AgentCommandModel) -> AgentCommandModel:
        now = datetime.now(timezone.utc)
        stale_claim = command.status == "CLAIMED" and command.lease_until is not None and command.lease_until <= now
        if command.status == "QUEUED" or stale_claim:
            command.status = "CLAIMED"
            command.claimed_at = now
            command.lease_until = now + timedelta(seconds=COMMAND_LEASE_SECONDS)
            command.attempt_count = int(command.attempt_count or 0) + 1
            await self._session.commit(); await self._session.refresh(command)
        return command

    async def complete_agent_command(self, command: AgentCommandModel, *, result: dict) -> AgentCommandModel:
        if command.status not in {"QUEUED", "CLAIMED"}: raise ValueError("Command is not active.")
        command.status = "COMPLETED" if bool(result.get("ok")) else "FAILED"
        command.result = result; command.completed_at = datetime.now(timezone.utc); command.lease_until = None
        action = await self.get(command.action_id)
        if action is not None and action.status == "APPROVED":
            action.status = "EXECUTED" if command.status == "COMPLETED" else "FAILED"
            action.executed_at = command.completed_at; action.execution_result = result; action.version += 1
        self._session.add(SoarAuditModel(audit_id=str(uuid.uuid4()), action_id=command.action_id, actor=f"agent:{command.agent_id}", event=command.status, details={"command_id":command.command_id,"attempt_count":command.attempt_count, **result}))
        await self._session.commit(); await self._session.refresh(command); return command

    async def mark_executed(self, action: SoarActionModel, *, actor: str, result: dict) -> SoarActionModel:
        if action.status != "APPROVED": raise ValueError("Action must be APPROVED before execution.")
        action.status = "EXECUTED"; action.executed_at = datetime.now(timezone.utc); action.execution_result = result; action.version += 1
        self._session.add(SoarAuditModel(audit_id=str(uuid.uuid4()), action_id=action.action_id, actor=actor, event="EXECUTED", details=result))
        await self._session.commit(); await self._session.refresh(action); return action

    async def audit(self, action_id: str) -> list[SoarAuditModel]:
        result = await self._session.execute(select(SoarAuditModel).where(SoarAuditModel.action_id == action_id).order_by(SoarAuditModel.created_at))
        return list(result.scalars().all())
