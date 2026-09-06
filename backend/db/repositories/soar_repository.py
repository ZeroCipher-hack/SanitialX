"""Repository for approval-based SOAR actions and audit events."""
from __future__ import annotations
from datetime import datetime, timezone
import uuid
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from db.models.soar import SoarActionModel, SoarAuditModel

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

    async def mark_executed(self, action: SoarActionModel, *, actor: str, result: dict) -> SoarActionModel:
        if action.status != "APPROVED": raise ValueError("Action must be APPROVED before execution.")
        action.status = "EXECUTED"; action.executed_at = datetime.now(timezone.utc); action.execution_result = result; action.version += 1
        self._session.add(SoarAuditModel(audit_id=str(uuid.uuid4()), action_id=action.action_id, actor=actor, event="EXECUTED", details=result))
        await self._session.commit(); await self._session.refresh(action); return action

    async def audit(self, action_id: str) -> list[SoarAuditModel]:
        result = await self._session.execute(select(SoarAuditModel).where(SoarAuditModel.action_id == action_id).order_by(SoarAuditModel.created_at))
        return list(result.scalars().all())
