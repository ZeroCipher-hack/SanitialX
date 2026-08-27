"""
IncidentService — manages incident lifecycle and state transitions.

Architecture Invariants (architecture.md #6 & #7):
- All Incident state transitions belong exclusively to IncidentService.
  API routers or other callers MUST NOT directly mutate incident status.
- Validates allowed state transitions.
- Enforces optimistic concurrency by passing expected_version to repository.update().
- Returns new immutable Incident instances on change.
"""

from __future__ import annotations

from datetime import datetime, timezone

from core.errors import ValidationError
from incidents.enums import IncidentStatus
from incidents.models import Incident
from incidents.repository import IncidentRepository


_ALLOWED_TRANSITIONS: dict[IncidentStatus, set[IncidentStatus]] = {
    IncidentStatus.OPEN: {
        IncidentStatus.INVESTIGATING,
        IncidentStatus.RESOLVED,
        IncidentStatus.CLOSED,
    },
    IncidentStatus.INVESTIGATING: {
        IncidentStatus.RESOLVED,
        IncidentStatus.CLOSED,
    },
    IncidentStatus.RESOLVED: {
        IncidentStatus.CLOSED,
        IncidentStatus.OPEN,
    },
    IncidentStatus.CLOSED: {
        IncidentStatus.OPEN,
    },
}


class IncidentService:
    """Domain service controlling Incident creation, retrieval and transitions."""

    def __init__(self, repository: IncidentRepository) -> None:
        self._repository = repository

    async def create_incident(self, incident: Incident) -> Incident:
        """Create and persist a new Incident."""
        return await self._repository.create(incident)

    async def get_incident(self, incident_id: str) -> Incident | None:
        """Retrieve an Incident by ID."""
        return await self._repository.get_by_id(incident_id)

    async def list_incidents(self, limit: int = 100, offset: int = 0) -> list[Incident]:
        """List incidents through the domain service boundary."""
        return await self._repository.list_all(limit=limit, offset=offset)

    async def transition_status(
        self,
        incident_id: str,
        new_status: IncidentStatus,
        expected_version: int | None = None,
    ) -> Incident:
        """Transition an incident to a permitted status with OCC."""
        current = await self._repository.get_by_id(incident_id)
        if current is None:
            raise KeyError(f"Incident '{incident_id}' not found.")

        if current.status == new_status:
            return current

        allowed = _ALLOWED_TRANSITIONS.get(current.status, set())
        if new_status not in allowed:
            raise ValidationError(
                f"Illegal incident status transition: cannot move from "
                f"'{current.status.value}' to '{new_status.value}'."
            )

        now = datetime.now(timezone.utc)
        ver_check = expected_version if expected_version is not None else current.version
        updated_model = Incident(
            incident_id=current.incident_id,
            title=current.title,
            description=current.description,
            severity=current.severity,
            status=new_status,
            version=current.version + 1,
            created_at=current.created_at,
            updated_at=now,
            source_ip=current.source_ip,
            destination_ip=current.destination_ip,
            triggering_detection_ids=current.triggering_detection_ids,
            context=current.context,
        )

        return await self._repository.update(updated_model, expected_version=ver_check)
