"""Automated Incident Investigation Reports API Router for SanitialX."""
from __future__ import annotations
import asyncio, logging
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import HTMLResponse
from sqlalchemy.ext.asyncio import AsyncSession
from api.deps import get_current_user, get_incident_repository, get_db_session
from core.config import get_settings
from core.security import TokenPayload
from db.repositories.incident_repository import PostgresIncidentRepository
from db.repositories.soar_repository import PostgresSoarRepository
from db.repositories.vulnerability_repository import PostgresVulnerabilityRepository
from services.ai_analysis import AIIncidentAnalysis, analyze_incident, fallback_analysis
from services.report_renderer import render_incident_report
logger=logging.getLogger(__name__);router=APIRouter(prefix="/reports",tags=["Investigation Reports"])

def _report_fields(inc,analysis:AIIncidentAnalysis)->dict:
    context=inc.context or {}
    return {"report_id":f"REP-{inc.incident_id}","incident_id":inc.incident_id,"title":inc.title,"severity":inc.severity.value,"status":inc.status.value,"created_at":inc.created_at.isoformat(),"updated_at":inc.updated_at.isoformat(),"source_ip":inc.source_ip,"destination_ip":inc.destination_ip,"triggering_detection_ids":inc.triggering_detection_ids,"executive_summary":analysis.executive_summary,"threat_classification":analysis.threat_classification,"confidence_score":analysis.confidence_score,"key_findings":analysis.key_findings,"indicators_of_compromise":analysis.indicators_of_compromise,"initial_access_vector":analysis.initial_access_vector,"affected_assets":analysis.affected_assets,"observed_techniques":analysis.observed_techniques,"honeypot_engagement":analysis.honeypot_engagement,"simulated_data_loss":analysis.simulated_data_loss,"overall_risk_score":analysis.overall_risk_score,"recommended_actions":analysis.recommended_actions,"graph_nodes":context.get("graph_nodes",[]),"graph_edges":context.get("graph_edges",[])}

async def _analyze(inc)->AIIncidentAnalysis:
    settings=get_settings()
    if not settings.gemini_api_key:return fallback_analysis(inc)
    try:return await asyncio.to_thread(analyze_incident,inc,api_key=settings.gemini_api_key,model=settings.gemini_model)
    except Exception:logger.exception("Gemini incident analysis failed for %s",inc.incident_id);return fallback_analysis(inc)

async def _vulnerability_evidence(session:AsyncSession,inc)->list[dict]:
    """Return deterministic exposure evidence when an incident came from CVE correlation."""
    context=inc.context or {};cve_id=str(context.get("cve_id") or "").upper();agent_id=str(context.get("agent_id") or "")
    if not cve_id or not agent_id:return []
    repo=PostgresVulnerabilityRepository(session);vulnerability=await repo.get_vulnerability(cve_id)
    exposures=await repo.list_asset_exposures(agent_id=agent_id,min_risk_score=0,limit=500)
    exposure=next((item for item in exposures if item.cve_id.upper()==cve_id),None)
    if vulnerability is None or exposure is None:return []
    return [{"cve_id":vulnerability.cve_id,"agent_id":agent_id,"severity":vulnerability.severity,"cvss_score":vulnerability.cvss_score,"known_exploited":vulnerability.known_exploited,"exploit_available":vulnerability.exploit_available,"exposure_status":exposure.status,"risk_score":exposure.risk_score,"match_confidence":exposure.match_confidence,"internet_exposed":exposure.internet_exposed,"matched_software":exposure.matched_software,"rationale":exposure.rationale,"event_evidence_score":context.get("event_evidence_score")}]

@router.get("")
async def list_reports(repo:Annotated[PostgresIncidentRepository,Depends(get_incident_repository)],_user:Annotated[TokenPayload,Depends(get_current_user)],limit:int=Query(default=50,ge=1,le=500),offset:int=Query(default=0,ge=0)):
    incidents=await repo.list_all(limit=limit,offset=offset);reports=[]
    for inc in incidents:
        context=inc.context or {};reports.append({"report_id":f"REP-{inc.incident_id}","incident_id":inc.incident_id,"title":inc.title,"severity":inc.severity.value,"status":inc.status.value,"created_at":inc.created_at.isoformat(),"updated_at":inc.updated_at.isoformat(),"executive_summary":context.get("executive_summary","Open the incident to run Gemini AI analysis."),"overall_risk_score":context.get("overall_risk_score",0),"observed_techniques_count":len(context.get("observed_techniques",[])),"affected_assets":context.get("affected_assets",[])})
    return reports

@router.get("/{incident_id}")
async def get_report_detail(incident_id:str,repo:Annotated[PostgresIncidentRepository,Depends(get_incident_repository)],_user:Annotated[TokenPayload,Depends(get_current_user)]):
    inc=await repo.get_by_id(incident_id)
    if inc is None:raise HTTPException(status_code=404,detail=f"Report for incident '{incident_id}' not found.")
    return _report_fields(inc,await _analyze(inc))

@router.get("/{incident_id}/print",response_class=HTMLResponse)
async def get_printable_report(incident_id:str,session:Annotated[AsyncSession,Depends(get_db_session)],_user:Annotated[TokenPayload,Depends(get_current_user)]):
    """Render a self-contained A4 SOC report; browser Print -> Save as PDF produces the PDF artifact."""
    inc=await PostgresIncidentRepository(session).get_by_id(incident_id)
    if inc is None:raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail=f"Report for incident '{incident_id}' not found.")
    report=_report_fields(inc,await _analyze(inc));soar_repo=PostgresSoarRepository(session);actions=await soar_repo.list(incident_id=incident_id,limit=500)
    action_rows=[{"action_type":a.action_type,"target_value":a.target_value,"status":a.status,"approved_by":a.approved_by,"rejected_by":a.rejected_by} for a in actions]
    timeline=[{"timestamp":inc.created_at.isoformat(),"event":"INCIDENT_CREATED","actor":"SanitialX","details":inc.title},{"timestamp":inc.updated_at.isoformat(),"event":"INCIDENT_UPDATED","actor":"SanitialX","details":inc.status.value}]
    for action in actions:
        for audit in await soar_repo.audit(action.action_id):timeline.append({"timestamp":audit.created_at.isoformat(),"event":audit.event,"actor":audit.actor,"details":audit.details})
    timeline.sort(key=lambda item:item["timestamp"]);vulnerability_evidence=await _vulnerability_evidence(session,inc)
    return HTMLResponse(render_incident_report(report,soar_actions=action_rows,timeline=timeline,vulnerability_evidence=vulnerability_evidence),headers={"Content-Disposition":f'inline; filename="{report["report_id"]}.html"',"Cache-Control":"no-store"})
