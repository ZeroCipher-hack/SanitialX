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


# Allowed status state transition map
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
    """Domain service controlling Incident creation and state transitions.

    Usage::

        service = IncidentService(repository)
        incident = await service.create_incident(new_incident)
        updated = await service.transition_status(incident_id, IncidentStatus.INVESTIGATING)
    """

    def __init__(self, repository: IncidentRepository) -> None:
        self._repository = repository

    async def create_incident(self, incident: Incident) -> Incident:
        """Create and persist a new Incident."""
        return await self._repository.create(incident)

    async def get_incident(self, incident_id: str) -> Incident | None:
        """Retrieve an Incident by ID."""
        return await self._repository.get_by_id(incident_id)

    async def transition_status(
        self,
        incident_id: str,
        new_status: IncidentStatus,
    ) -> Incident:
        """Transition an incident to a new status.

        Validates that the status transition is permitted, increments the
        version counter, updates timestamp, and calls repository.update() with
        the expected previous version.

        Raises:
            KeyError: if incident_id is not found.
            ValidationError: if the status transition is prohibited.
            IncidentConflictError: if a concurrent update modified the version.
        """
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

        # Construct updated immutable Incident with incremented version
        now = datetime.now(timezone.utc)
        expected_version = current.version
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

        return await self._repository.update(updated_model, expected_version=expected_version)
