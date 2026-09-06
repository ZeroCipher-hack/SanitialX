"""Postgres / Async SQLAlchemy repository for managed assets / endpoint agents."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import desc, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from db.models.agent import AgentModel


class PostgresAgentRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def upsert_agent(self, agent_data: dict[str, Any]) -> AgentModel:
        agent_id = agent_data["agent_id"]
        existing = await self._session.get(AgentModel, agent_id)
        if existing:
            for k, v in agent_data.items():
                if k == "first_seen":
                    continue
                if hasattr(existing, k):
                    setattr(existing, k, v)
            model = existing
        else:
            model = AgentModel(**agent_data)
            self._session.add(model)
        await self._session.commit(); await self._session.refresh(model); return model

    async def enroll_agent(self, agent_data: dict[str, Any], token_hash: str) -> AgentModel:
        now = datetime.now(timezone.utc); agent_id = agent_data["agent_id"]
        model = await self._session.get(AgentModel, agent_id)
        if model is None:
            model = AgentModel(**agent_data,status="ONLINE",source="agent",lifecycle_status="DISCOVERED",agent_token_hash=token_hash,enrolled_at=now,last_seen=now)
            self._session.add(model)
        else:
            for key in ("hostname","ip_address","os","agent_version"):
                if key in agent_data: setattr(model,key,agent_data[key])
            model.agent_token_hash=token_hash; model.enrolled_at=now; model.last_seen=now; model.status="ONLINE"
        await self._session.commit(); await self._session.refresh(model); return model

    async def heartbeat_agent(self, agent_id: str, *, cpu_usage: float, memory_usage: float, agent_version: str | None = None, ip_address: str | None = None) -> AgentModel | None:
        model = await self._session.get(AgentModel, agent_id)
        if model is None: return None
        model.last_seen=datetime.now(timezone.utc); model.status="ONLINE"; model.cpu_usage=cpu_usage; model.memory_usage=memory_usage
        if agent_version: model.agent_version=agent_version
        if ip_address: model.ip_address=ip_address
        await self._session.commit(); await self._session.refresh(model); return model

    async def record_forwarded_events(self, agent_id: str, count: int) -> AgentModel | None:
        """Update endpoint activity only after an event batch was accepted for processing."""
        model = await self._session.get(AgentModel, agent_id)
        if model is None: return None
        model.events_count = max(0, int(model.events_count or 0)) + max(0, int(count))
        model.last_seen = datetime.now(timezone.utc)
        model.status = "ONLINE"
        await self._session.commit(); await self._session.refresh(model); return model

    async def mark_stale_agents_offline(self, *, timeout_seconds: int) -> int:
        """Mark enrolled ONLINE agents OFFLINE after missing their heartbeat deadline."""
        stale_before = datetime.now(timezone.utc) - timedelta(seconds=max(1, timeout_seconds))
        result = await self._session.execute(
            update(AgentModel)
            .where(
                AgentModel.agent_token_hash.is_not(None),
                AgentModel.status == "ONLINE",
                AgentModel.last_seen < stale_before,
            )
            .values(status="OFFLINE")
        )
        await self._session.commit()
        return int(result.rowcount or 0)

    async def list_agents(self,limit:int=50,offset:int=0,*,status:str|None=None,asset_type:str|None=None,criticality:str|None=None,environment:str|None=None,lifecycle_status:str|None=None,internet_exposed:bool|None=None,query:str|None=None)->list[dict[str,Any]]:
        stmt=select(AgentModel)
        if status: stmt=stmt.where(AgentModel.status==status.upper())
        if asset_type: stmt=stmt.where(AgentModel.asset_type==asset_type.upper())
        if criticality: stmt=stmt.where(AgentModel.criticality==criticality.upper())
        if environment: stmt=stmt.where(AgentModel.environment==environment.upper())
        if lifecycle_status: stmt=stmt.where(AgentModel.lifecycle_status==lifecycle_status.upper())
        if internet_exposed is not None: stmt=stmt.where(AgentModel.internet_exposed==internet_exposed)
        if query:
            pattern=f"%{query.strip()}%"; stmt=stmt.where(or_(AgentModel.hostname.ilike(pattern),AgentModel.ip_address.ilike(pattern),AgentModel.os.ilike(pattern),AgentModel.owner.ilike(pattern)))
        result=await self._session.execute(stmt.order_by(desc(AgentModel.risk_score),AgentModel.hostname).limit(limit).offset(offset)); return [row.to_dict() for row in result.scalars().all()]

    async def get_inventory_summary(self,*,stale_after_hours:int=24)->dict[str,int]:
        stale_before=datetime.now(timezone.utc)-timedelta(hours=max(stale_after_hours,1))
        total=await self._session.scalar(select(func.count()).select_from(AgentModel)); critical=await self._session.scalar(select(func.count()).select_from(AgentModel).where(AgentModel.criticality=="CRITICAL")); internet_facing=await self._session.scalar(select(func.count()).select_from(AgentModel).where(AgentModel.internet_exposed.is_(True))); offline=await self._session.scalar(select(func.count()).select_from(AgentModel).where(AgentModel.status=="OFFLINE")); high_risk=await self._session.scalar(select(func.count()).select_from(AgentModel).where(AgentModel.risk_score>=70)); production=await self._session.scalar(select(func.count()).select_from(AgentModel).where(AgentModel.environment=="PRODUCTION")); managed=await self._session.scalar(select(func.count()).select_from(AgentModel).where(AgentModel.lifecycle_status=="MANAGED")); retired=await self._session.scalar(select(func.count()).select_from(AgentModel).where(AgentModel.lifecycle_status=="RETIRED")); stale_inventory=await self._session.scalar(select(func.count()).select_from(AgentModel).where(or_(AgentModel.inventory_updated_at.is_(None),AgentModel.inventory_updated_at<stale_before)))
        return {"total_assets":int(total or 0),"critical_assets":int(critical or 0),"internet_facing_assets":int(internet_facing or 0),"offline_assets":int(offline or 0),"high_risk_assets":int(high_risk or 0),"production_assets":int(production or 0),"managed_assets":int(managed or 0),"retired_assets":int(retired or 0),"stale_inventory_assets":int(stale_inventory or 0)}

    async def get_agent(self,agent_id:str)->dict[str,Any]|None:
        model=await self._session.get(AgentModel,agent_id); return model.to_dict() if model else None
    async def get_agent_model(self,agent_id:str)->AgentModel|None: return await self._session.get(AgentModel,agent_id)
    async def update_asset_metadata(self,agent_id:str,changes:dict[str,Any])->dict[str,Any]|None:
        model=await self._session.get(AgentModel,agent_id)
        if model is None:return None
        allowed={"asset_type","criticality","environment","owner","internet_exposed","tags","lifecycle_status"}
        for key,value in changes.items():
            if key in allowed:setattr(model,key,value)
        await self._session.commit();await self._session.refresh(model);return model.to_dict()
    async def touch_inventory(self,agent_id:str,*,mark_managed:bool=True)->dict[str,Any]|None:
        model=await self._session.get(AgentModel,agent_id)
        if model is None:return None
        model.inventory_updated_at=datetime.now(timezone.utc)
        if mark_managed and model.lifecycle_status=="DISCOVERED":model.lifecycle_status="MANAGED"
        await self._session.commit();await self._session.refresh(model);return model.to_dict()
    async def get_agent_by_ip(self,ip_address:str|None)->dict[str,Any]|None:
        if not ip_address:return None
        result=await self._session.execute(select(AgentModel).where(AgentModel.ip_address==ip_address).limit(1)); model=result.scalar_one_or_none();return model.to_dict() if model else None
