"""
IncidentRepository abstraction for SentinelX.

Defines the contract for persistent storage of Incidents.
Must enforce optimistic concurrency control on update (raise IncidentConflictError
if expected_version does not match stored version).

Pure domain interface — no infrastructure imports allowed.
"""

from __future__ import annotations

import abc

from incidents.models import Incident


class IncidentRepository(abc.ABC):
    """Abstract repository interface for Incidents.

    Invariants:
    - update must check expected_version and raise IncidentConflictError on mismatch.
    - No Postgres dependency here (PostgreSQL implementation is Phase 10).
    """

    @abc.abstractmethod
    async def create(self, incident: Incident) -> Incident:
        """Persist a new Incident."""

    @abc.abstractmethod
    async def get_by_id(self, incident_id: str) -> Incident | None:
        """Fetch an Incident by ID, or None if not found."""

    @abc.abstractmethod
    async def update(self, incident: Incident, expected_version: int) -> Incident:
        """Update an existing Incident.

        Must atomically verify that stored version == expected_version,
        increment version, and save the updated Incident.

        Raises:
            IncidentConflictError: if stored version != expected_version.
            KeyError: if incident_id is not found.
        """

    @abc.abstractmethod
    async def list_all(self, limit: int = 100, offset: int = 0) -> list[Incident]:
        """List persisted incidents."""
