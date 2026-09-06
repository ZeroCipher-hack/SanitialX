"""Managed assets / endpoint agents API router for SanitialX."""

from __future__ import annotations

import hmac
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import get_current_user, get_db_session, require_role
from core.config import get_settings
from core.security import TokenPayload, generate_agent_token, hash_agent_token, verify_agent_token
from db.repositories.agent_repository import PostgresAgentRepository
from db.repositories.vulnerability_repository import PostgresVulnerabilityRepository
from event_bus.redis_bus import RedisEventBus
from events.models import NormalizedEvent

router = APIRouter(prefix="/agents", tags=["Assets & Endpoints"])


class AgentEnrollmentPayload(BaseModel):
    agent_id: str = Field(..., min_length=3, max_length=64)
    hostname: str = Field(..., min_length=1, max_length=100)
    ip_address: str = Field(..., min_length=3, max_length=45)
    os: str = Field(..., min_length=1, max_length=100)
    agent_version: str | None = Field(default=None, max_length=40)


class AgentHeartbeatPayload(BaseModel):
    cpu_usage: float = Field(default=0.0, ge=0, le=100)
    memory_usage: float = Field(default=0.0, ge=0, le=100)
    agent_version: str | None = Field(default=None, max_length=40)
    ip_address: str | None = Field(default=None, min_length=3, max_length=45)


class AgentEventItem(BaseModel):
    event_id: str | None = Field(default=None, max_length=64)
    event_type: str = Field(..., min_length=1, max_length=80)
    timestamp: datetime
    severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] = "INFO"
    source_ip: str | None = Field(default=None, max_length=45)
    destination_ip: str | None = Field(default=None, max_length=45)
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = Field(default=None, max_length=32)
    message: str | None = Field(default=None, max_length=4000)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentEventBatch(BaseModel):
    events: list[AgentEventItem] = Field(..., min_length=1, max_length=500)


class SoftwareInventoryItem(BaseModel):
    vendor: str = Field(default="", max_length=120)
    product: str = Field(..., min_length=1, max_length=160)
    version: str = Field(..., min_length=1, max_length=80)
    package_name: str | None = Field(default=None, max_length=180)
    ecosystem: str | None = Field(default=None, max_length=40)
    purl: str | None = Field(default=None, max_length=512)
    cpe: str | None = Field(default=None, max_length=512)
    source: str = Field(default="agent", max_length=40)

    @field_validator("ecosystem")
    @classmethod
    def normalize_ecosystem(cls, value: str | None) -> str | None:
        if value is None: return None
        normalized = value.strip().lower(); return normalized or None

    @field_validator("purl")
    @classmethod
    def validate_purl(cls, value: str | None) -> str | None:
        if value is None: return None
        normalized = value.strip()
        if normalized and not normalized.startswith("pkg:"): raise ValueError("purl must start with 'pkg:'")
        return normalized or None

    @field_validator("cpe")
    @classmethod
    def validate_cpe(cls, value: str | None) -> str | None:
        if value is None: return None
        normalized = value.strip()
        if normalized and not normalized.startswith("cpe:2.3:"): raise ValueError("cpe must use CPE 2.3 format")
        return normalized or None


class SoftwareInventoryPayload(BaseModel):
    software: list[SoftwareInventoryItem] = Field(default_factory=list, max_length=5000)


class AssetMetadataUpdate(BaseModel):
    asset_type: Literal["ENDPOINT", "SERVER", "WORKSTATION", "CLOUD", "NETWORK", "CONTAINER", "OTHER"] | None = None
    criticality: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None
    environment: Literal["PRODUCTION", "STAGING", "DEVELOPMENT", "TEST", "UNKNOWN"] | None = None
    lifecycle_status: Literal["DISCOVERED", "MANAGED", "RETIRED", "EXCLUDED"] | None = None
    owner: str | None = Field(default=None, max_length=160)
    internet_exposed: bool | None = None
    tags: list[str] | None = Field(default=None, max_length=50)

    @field_validator("tags")
    @classmethod
    def normalize_tags(cls, value: list[str] | None) -> list[str] | None:
        if value is None: return None
        cleaned=[item.strip().lower() for item in value if item.strip()]
        if any(len(item)>64 for item in cleaned): raise ValueError("each tag must be at most 64 characters")
        return list(dict.fromkeys(cleaned))


async def _require_agent(repo: PostgresAgentRepository, agent_id: str, token: str | None):
    model = await repo.get_agent_model(agent_id)
    if model is None: raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found.")
    if not token or not verify_agent_token(token, model.agent_token_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid agent token.")
    return model


def _software_to_dict(item: Any) -> dict[str, Any]:
    return {"vendor":item.vendor,"product":item.product,"version":item.version,"package_name":item.package_name,"ecosystem":item.ecosystem,"purl":item.purl,"cpe":item.cpe,"source":item.source,"last_seen":item.last_seen}


@router.post("/enroll", status_code=status.HTTP_201_CREATED)
async def enroll_agent(payload:AgentEnrollmentPayload,session:Annotated[AsyncSession,Depends(get_db_session)],enrollment_key:Annotated[str|None,Header(alias="X-Enrollment-Key")]=None)->dict[str,Any]:
    settings=get_settings()
    if not enrollment_key or not hmac.compare_digest(enrollment_key,settings.api_key): raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Invalid enrollment key.")
    raw_token=generate_agent_token(); model=await PostgresAgentRepository(session).enroll_agent(payload.model_dump(),hash_agent_token(raw_token))
    return {"agent_id":model.agent_id,"agent_token":raw_token,"status":model.status,"enrolled_at":model.enrolled_at.isoformat() if model.enrolled_at else None,"heartbeat_interval_seconds":30}


@router.post("/{agent_id}/heartbeat")
async def agent_heartbeat(agent_id:str,payload:AgentHeartbeatPayload,session:Annotated[AsyncSession,Depends(get_db_session)],agent_token:Annotated[str|None,Header(alias="X-Agent-Token")]=None)->dict[str,Any]:
    repo=PostgresAgentRepository(session); await _require_agent(repo,agent_id,agent_token)
    updated=await repo.heartbeat_agent(agent_id,cpu_usage=payload.cpu_usage,memory_usage=payload.memory_usage,agent_version=payload.agent_version,ip_address=payload.ip_address); assert updated is not None
    return {"agent_id":updated.agent_id,"status":updated.status,"last_seen":updated.last_seen.isoformat(),"next_heartbeat_seconds":30}


@router.put("/{agent_id}/inventory/software")
async def agent_replace_software_inventory(agent_id:str,payload:SoftwareInventoryPayload,session:Annotated[AsyncSession,Depends(get_db_session)],agent_token:Annotated[str|None,Header(alias="X-Agent-Token")]=None)->dict[str,Any]:
    agent_repo=PostgresAgentRepository(session); await _require_agent(agent_repo,agent_id,agent_token)
    items=await PostgresVulnerabilityRepository(session).replace_software_inventory(agent_id,[item.model_dump() for item in payload.software]); asset=await agent_repo.touch_inventory(agent_id)
    return {"agent_id":agent_id,"software_count":len(items),"inventory_updated_at":asset.get("inventory_updated_at") if asset else None,"lifecycle_status":asset.get("lifecycle_status") if asset else None}


@router.post("/{agent_id}/events", status_code=status.HTTP_202_ACCEPTED)
async def agent_forward_events(agent_id:str,payload:AgentEventBatch,session:Annotated[AsyncSession,Depends(get_db_session)],agent_token:Annotated[str|None,Header(alias="X-Agent-Token")]=None)->dict[str,Any]:
    agent_repo=PostgresAgentRepository(session); agent=await _require_agent(agent_repo,agent_id,agent_token)
    bus=RedisEventBus.from_url(get_settings().redis_url)
    try:
        for item in payload.events:
            metadata=dict(item.metadata); metadata["severity"]=item.severity; metadata["agent_id"]=agent_id; metadata.setdefault("host",agent.hostname)
            if item.message: metadata["message"]=item.message
            kwargs={"event_type":item.event_type,"timestamp":item.timestamp,"source_ip":item.source_ip,"destination_ip":item.destination_ip,"source_port":item.source_port,"destination_port":item.destination_port,"protocol":item.protocol,"sensor_id":agent_id,"metadata":metadata}
            if item.event_id: kwargs["event_id"]=item.event_id
            await bus.publish(NormalizedEvent(**kwargs))
    finally:
        await bus.close()
    await agent_repo.record_forwarded_events(agent_id,len(payload.events))
    return {"agent_id":agent_id,"accepted":len(payload.events),"pipeline":"redis-stream -> detection -> correlation -> incident"}


@router.get("")
async def list_agents(session:Annotated[AsyncSession,Depends(get_db_session)],_user:Annotated[TokenPayload,Depends(get_current_user)],limit:int=Query(default=50,ge=1,le=500),offset:int=Query(default=0,ge=0),status_filter:str|None=Query(default=None,alias="status"),asset_type:str|None=None,criticality:str|None=None,environment:str|None=None,lifecycle_status:str|None=None,internet_exposed:bool|None=None,q:str|None=Query(default=None,max_length=160)):
    return await PostgresAgentRepository(session).list_agents(limit=limit,offset=offset,status=status_filter,asset_type=asset_type,criticality=criticality,environment=environment,lifecycle_status=lifecycle_status,internet_exposed=internet_exposed,query=q)


@router.get("/summary")
async def get_asset_summary(session:Annotated[AsyncSession,Depends(get_db_session)],_user:Annotated[TokenPayload,Depends(get_current_user)],stale_after_hours:int=Query(default=24,ge=1,le=720))->dict[str,int]:
    return await PostgresAgentRepository(session).get_inventory_summary(stale_after_hours=stale_after_hours)


@router.get("/{agent_id}")
async def get_asset_detail(agent_id:str,session:Annotated[AsyncSession,Depends(get_db_session)],_user:Annotated[TokenPayload,Depends(get_current_user)])->dict[str,Any]:
    agent_repo=PostgresAgentRepository(session); asset=await agent_repo.get_agent(agent_id)
    if asset is None: raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail=f"Asset '{agent_id}' not found.")
    vuln_repo=PostgresVulnerabilityRepository(session); software=await vuln_repo.list_software_inventory(agent_id); exposures=await vuln_repo.list_asset_exposures(agent_id=agent_id,limit=500); affected=[x for x in exposures if x.status=="AFFECTED"]; critical=[x for x in exposures if x.risk_score>=90]; high=[x for x in exposures if 70<=x.risk_score<90]
    return {**asset,"software_count":len(software),"exposure_summary":{"total":len(exposures),"affected":len(affected),"critical":len(critical),"high":len(high),"max_risk_score":max((x.risk_score for x in exposures),default=0)},"top_exposures":[{"cve_id":x.cve_id,"status":x.status,"risk_score":x.risk_score,"match_confidence":x.match_confidence,"internet_exposed":x.internet_exposed,"matched_software":x.matched_software} for x in exposures[:10]]}


@router.patch("/{agent_id}")
async def update_asset_metadata(agent_id:str,payload:AssetMetadataUpdate,session:Annotated[AsyncSession,Depends(get_db_session)],_user:Annotated[TokenPayload,Depends(require_role(["admin","analyst"]))])->dict[str,Any]:
    updated=await PostgresAgentRepository(session).update_asset_metadata(agent_id,payload.model_dump(exclude_unset=True))
    if updated is None: raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail=f"Asset '{agent_id}' not found.")
    return updated


@router.put("/{agent_id}/software")
async def replace_software_inventory(agent_id:str,payload:SoftwareInventoryPayload,session:Annotated[AsyncSession,Depends(get_db_session)],_user:Annotated[TokenPayload,Depends(get_current_user)])->dict[str,Any]:
    agent_repo=PostgresAgentRepository(session)
    if await agent_repo.get_agent(agent_id) is None: raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail=f"Agent '{agent_id}' not found.")
    items=await PostgresVulnerabilityRepository(session).replace_software_inventory(agent_id,[item.model_dump() for item in payload.software]); asset=await agent_repo.touch_inventory(agent_id)
    return {"agent_id":agent_id,"software_count":len(items),"inventory_updated_at":asset.get("inventory_updated_at") if asset else None,"lifecycle_status":asset.get("lifecycle_status") if asset else None,"software":[_software_to_dict(item) for item in items]}


@router.get("/{agent_id}/software")
async def get_software_inventory(agent_id:str,session:Annotated[AsyncSession,Depends(get_db_session)],_user:Annotated[TokenPayload,Depends(get_current_user)])->dict[str,Any]:
    agent_repo=PostgresAgentRepository(session)
    if await agent_repo.get_agent(agent_id) is None: raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail=f"Agent '{agent_id}' not found.")
    items=await PostgresVulnerabilityRepository(session).list_software_inventory(agent_id); return {"agent_id":agent_id,"software_count":len(items),"software":[_software_to_dict(item) for item in items]}
