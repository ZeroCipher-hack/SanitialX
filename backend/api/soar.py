"""Approval-based SOAR API. No destructive action executes without analyst approval."""
from __future__ import annotations
from typing import Annotated, Any, Literal
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from api.deps import get_current_user, get_db_session, require_role
from core.security import TokenPayload
from db.repositories.incident_repository import PostgresIncidentRepository
from db.repositories.soar_repository import PostgresSoarRepository

router = APIRouter(prefix="/soar", tags=["SOAR"])
CONTROLLED_ACTIONS = {"BLOCK_IP", "ISOLATE_HOST", "DISABLE_ACCOUNT", "KILL_PROCESS"}

class SoarActionCreate(BaseModel):
    incident_id: str = Field(..., min_length=3, max_length=36)
    action_type: Literal["ADD_WATCHLIST","COLLECT_FORENSICS","REQUEST_RESCAN","NOTIFY_ANALYST","BLOCK_IP","ISOLATE_HOST","DISABLE_ACCOUNT","KILL_PROCESS"]
    target_type: Literal["IP","ASSET","USER","PROCESS","INCIDENT"]
    target_value: str = Field(..., min_length=1, max_length=255)
    parameters: dict[str, Any] = Field(default_factory=dict)
    risk_level: Literal["LOW","MEDIUM","HIGH","CRITICAL"] = "MEDIUM"
    reason: str = Field(..., min_length=3, max_length=2000)

class DecisionPayload(BaseModel):
    note: str = Field(default="", max_length=2000)

def serialize(action) -> dict[str, Any]:
    return {"action_id":action.action_id,"incident_id":action.incident_id,"action_type":action.action_type,"target_type":action.target_type,"target_value":action.target_value,"parameters":action.parameters,"status":action.status,"risk_level":action.risk_level,"reason":action.reason,"requested_by":action.requested_by,"approved_by":action.approved_by,"rejected_by":action.rejected_by,"execution_result":action.execution_result,"created_at":action.created_at,"decided_at":action.decided_at,"executed_at":action.executed_at,"version":action.version}

@router.post("/actions", status_code=status.HTTP_201_CREATED)
async def create_action(payload:SoarActionCreate,session:Annotated[AsyncSession,Depends(get_db_session)],user:Annotated[TokenPayload,Depends(require_role(["admin","analyst"]))]):
    incident = await PostgresIncidentRepository(session).get_by_id(payload.incident_id)
    if incident is None: raise HTTPException(status_code=404,detail="Incident not found.")
    action = await PostgresSoarRepository(session).create_action(payload.model_dump(), user.sub)
    return serialize(action)

@router.get("/actions")
async def list_actions(session:Annotated[AsyncSession,Depends(get_db_session)],_user:Annotated[TokenPayload,Depends(get_current_user)],incident_id:str|None=None,status_filter:str|None=Query(default=None,alias="status"),limit:int=Query(default=100,ge=1,le=500)):
    actions=await PostgresSoarRepository(session).list(incident_id=incident_id,status=status_filter,limit=limit)
    return [serialize(x) for x in actions]

@router.get("/actions/{action_id}")
async def get_action(action_id:str,session:Annotated[AsyncSession,Depends(get_db_session)],_user:Annotated[TokenPayload,Depends(get_current_user)]):
    action=await PostgresSoarRepository(session).get(action_id)
    if action is None: raise HTTPException(status_code=404,detail="SOAR action not found.")
    return serialize(action)

@router.post("/actions/{action_id}/approve")
async def approve_action(action_id:str,payload:DecisionPayload,session:Annotated[AsyncSession,Depends(get_db_session)],user:Annotated[TokenPayload,Depends(require_role(["admin","analyst"]))]):
    repo=PostgresSoarRepository(session); action=await repo.get(action_id)
    if action is None: raise HTTPException(status_code=404,detail="SOAR action not found.")
    try: action=await repo.decide(action,approve=True,actor=user.sub,note=payload.note)
    except ValueError as exc: raise HTTPException(status_code=409,detail=str(exc)) from exc
    return serialize(action)

@router.post("/actions/{action_id}/reject")
async def reject_action(action_id:str,payload:DecisionPayload,session:Annotated[AsyncSession,Depends(get_db_session)],user:Annotated[TokenPayload,Depends(require_role(["admin","analyst"]))]):
    repo=PostgresSoarRepository(session); action=await repo.get(action_id)
    if action is None: raise HTTPException(status_code=404,detail="SOAR action not found.")
    try: action=await repo.decide(action,approve=False,actor=user.sub,note=payload.note)
    except ValueError as exc: raise HTTPException(status_code=409,detail=str(exc)) from exc
    return serialize(action)

@router.post("/actions/{action_id}/execute")
async def execute_action(action_id:str,session:Annotated[AsyncSession,Depends(get_db_session)],user:Annotated[TokenPayload,Depends(require_role(["admin","analyst"]))]):
    repo=PostgresSoarRepository(session); action=await repo.get(action_id)
    if action is None: raise HTTPException(status_code=404,detail="SOAR action not found.")
    if action.status != "APPROVED": raise HTTPException(status_code=409,detail="Action must be APPROVED before execution.")
    simulated = action.action_type in CONTROLLED_ACTIONS
    result={"ok":True,"mode":"SIMULATED" if simulated else "SAFE_LOCAL","action_type":action.action_type,"target":action.target_value,"message":"Execution recorded; destructive endpoint control is not enabled in SOAR foundation v1." if simulated else "Safe response action recorded successfully."}
    action=await repo.mark_executed(action,actor=user.sub,result=result)
    return serialize(action)

@router.get("/actions/{action_id}/audit")
async def get_audit(action_id:str,session:Annotated[AsyncSession,Depends(get_db_session)],_user:Annotated[TokenPayload,Depends(get_current_user)]):
    repo=PostgresSoarRepository(session)
    if await repo.get(action_id) is None: raise HTTPException(status_code=404,detail="SOAR action not found.")
    rows=await repo.audit(action_id)
    return [{"audit_id":x.audit_id,"action_id":x.action_id,"actor":x.actor,"event":x.event,"details":x.details,"created_at":x.created_at} for x in rows]
