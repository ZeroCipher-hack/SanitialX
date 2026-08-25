"""
Incidents API router for SentinelX.

Endpoints:
- GET /incidents (paginated, authenticated)
- GET /incidents/{incident_id} (authenticated)
- PATCH /incidents/{incident_id}/status (requires analyst/admin role, optimistic concurrency handling)
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from api.deps import get_current_user, get_incident_service, require_role
from api.schemas import IncidentResponse, IncidentStatusUpdate
from core.errors import IncidentConflictError, ValidationError
from core.security import TokenPayload
from incidents.service import IncidentService

router = APIRouter(prefix="/incidents", tags=["Incidents"])


@router.get("", response_model=list[IncidentResponse])
async def list_incidents(
    service: Annotated[IncidentService, Depends(get_incident_service)],
    _user: Annotated[TokenPayload, Depends(get_current_user)],
    limit: int = Query(default=50, ge=1, le=1000, description="Page limit"),
    offset: int = Query(default=0, ge=0, description="Page offset"),
) -> list[IncidentResponse]:
    """List incidents with pagination."""
    incidents = await service._repository.list_all(limit=limit, offset=offset)
    return [
        IncidentResponse(
            incident_id=inc.incident_id,
            title=inc.title,
            description=inc.description,
            severity=inc.severity,
            status=inc.status,
            version=inc.version,
            created_at=inc.created_at,
            updated_at=inc.updated_at,
            source_ip=inc.source_ip,
            destination_ip=inc.destination_ip,
            triggering_detection_ids=inc.triggering_detection_ids,
            context=inc.context,
        )
        for inc in incidents
    ]


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(
    incident_id: str,
    service: Annotated[IncidentService, Depends(get_incident_service)],
    _user: Annotated[TokenPayload, Depends(get_current_user)],
) -> IncidentResponse:
    """Fetch a single incident by ID."""
    inc = await service.get_incident(incident_id)
    if inc is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found.",
        )
    return IncidentResponse(
        incident_id=inc.incident_id,
        title=inc.title,
        description=inc.description,
        severity=inc.severity,
        status=inc.status,
        version=inc.version,
        created_at=inc.created_at,
        updated_at=inc.updated_at,
        source_ip=inc.source_ip,
        destination_ip=inc.destination_ip,
        triggering_detection_ids=inc.triggering_detection_ids,
        context=inc.context,
    )


@router.patch("/{incident_id}/status", response_model=IncidentResponse)
async def update_incident_status(
    incident_id: str,
    payload: IncidentStatusUpdate,
    service: Annotated[IncidentService, Depends(get_incident_service)],
    _user: Annotated[TokenPayload, Depends(require_role(["admin", "analyst"]))],
) -> IncidentResponse:
    """Transition an incident's status. Requires admin or analyst role.

    Handles optimistic concurrency conflicts (IncidentConflictError) returning HTTP 409.
    """
    try:
        updated = await service.transition_status(
            incident_id=incident_id,
            new_status=payload.status,
        )
        return IncidentResponse(
            incident_id=updated.incident_id,
            title=updated.title,
            description=updated.description,
            severity=updated.severity,
            status=updated.status,
            version=updated.version,
            created_at=updated.created_at,
            updated_at=updated.updated_at,
            source_ip=updated.source_ip,
            destination_ip=updated.destination_ip,
            triggering_detection_ids=updated.triggering_detection_ids,
            context=updated.context,
        )
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found.",
        )
    except ValidationError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err),
        )
    except IncidentConflictError as conflict_err:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(conflict_err),
        )
