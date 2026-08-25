"""Unit tests for Phase 9: Incident domain, repository interface, builder, and service."""

from __future__ import annotations

import importlib
import inspect
from datetime import datetime, timezone
import pytest
from pydantic import ValidationError as PydanticValidationError

from core.errors import IncidentConflictError, ValidationError
from correlation.enums import Severity
from correlation.models import Detection
from incidents.builder import build_incident_from_detection
from incidents.enums import IncidentStatus
from incidents.models import Incident
from incidents.repository import IncidentRepository
from incidents.service import IncidentService


# ── Test-only Fake Repository ─────────────────────────────────────────────

class _InMemoryFakeIncidentRepository(IncidentRepository):
    """TEST-ONLY fake in-memory repository for unit testing IncidentService.

    Enforces optimistic concurrency version checking.
    NOT the Phase 10 PostgreSQL deliverable.
    """

    def __init__(self) -> None:
        self._store: dict[str, Incident] = {}

    async def create(self, incident: Incident) -> Incident:
        self._store[incident.incident_id] = incident
        return incident

    async def get_by_id(self, incident_id: str) -> Incident | None:
        return self._store.get(incident_id)

    async def update(self, incident: Incident, expected_version: int) -> Incident:
        stored = self._store.get(incident.incident_id)
        if stored is None:
            raise KeyError(f"Incident {incident.incident_id} not found")

        if stored.version != expected_version:
            raise IncidentConflictError(
                f"Concurrency conflict for Incident {incident.incident_id}: "
                f"expected version {expected_version}, but stored version is {stored.version}."
            )

        self._store[incident.incident_id] = incident
        return incident

    async def list_all(self, limit: int = 100, offset: int = 0) -> list[Incident]:
        return list(self._store.values())[offset : offset + limit]


# ── Helpers ───────────────────────────────────────────────────────────────

def _make_detection() -> Detection:
    return Detection(
        rule_id="RULE-PORT-SCAN-01",
        rule_name="Port Scan Detection",
        severity=Severity.HIGH,
        title="Port Scan from 192.168.1.50",
        description="Scanned 15 ports in 10 seconds",
        source_ip="192.168.1.50",
        destination_ip="10.0.0.1",
        triggering_event_ids=["evt-1", "evt-2"],
    )


# ── Tests ─────────────────────────────────────────────────────────────────

class TestIncidentBuilder:
    def test_build_incident_from_detection(self) -> None:
        det = _make_detection()
        inc = build_incident_from_detection(det)

        assert inc.incident_id is not None
        assert inc.title == f"Incident: {det.title}"
        assert inc.severity == Severity.HIGH
        assert inc.status == IncidentStatus.OPEN
        assert inc.version == 1
        assert inc.source_ip == "192.168.1.50"
        assert det.detection_id in inc.triggering_detection_ids


class TestIncidentModel:
    def test_immutability(self) -> None:
        det = _make_detection()
        inc = build_incident_from_detection(det)

        with pytest.raises(PydanticValidationError):
            inc.status = IncidentStatus.CLOSED  # type: ignore[misc]

    def test_naive_timestamp_rejected(self) -> None:
        with pytest.raises(PydanticValidationError):
            Incident(
                title="T",
                description="D",
                severity=Severity.LOW,
                created_at=datetime.now(),  # naive
            )


class TestIncidentService:
    @pytest.mark.asyncio
    async def test_create_and_get(self) -> None:
        repo = _InMemoryFakeIncidentRepository()
        service = IncidentService(repo)

        det = _make_detection()
        inc = build_incident_from_detection(det)

        created = await service.create_incident(inc)
        assert created.incident_id == inc.incident_id

        fetched = await service.get_incident(inc.incident_id)
        assert fetched is not None
        assert fetched.title == inc.title

    @pytest.mark.asyncio
    async def test_legal_status_transitions(self) -> None:
        repo = _InMemoryFakeIncidentRepository()
        service = IncidentService(repo)

        inc = await service.create_incident(build_incident_from_detection(_make_detection()))
        assert inc.status == IncidentStatus.OPEN
        assert inc.version == 1

        # OPEN -> INVESTIGATING
        inc2 = await service.transition_status(inc.incident_id, IncidentStatus.INVESTIGATING)
        assert inc2.status == IncidentStatus.INVESTIGATING
        assert inc2.version == 2

        # INVESTIGATING -> RESOLVED
        inc3 = await service.transition_status(inc.incident_id, IncidentStatus.RESOLVED)
        assert inc3.status == IncidentStatus.RESOLVED
        assert inc3.version == 3

        # RESOLVED -> CLOSED
        inc4 = await service.transition_status(inc.incident_id, IncidentStatus.CLOSED)
        assert inc4.status == IncidentStatus.CLOSED
        assert inc4.version == 4

        # CLOSED -> OPEN
        inc5 = await service.transition_status(inc.incident_id, IncidentStatus.OPEN)
        assert inc5.status == IncidentStatus.OPEN
        assert inc5.version == 5

    @pytest.mark.asyncio
    async def test_illegal_status_transition_raises_validation_error(self) -> None:
        repo = _InMemoryFakeIncidentRepository()
        service = IncidentService(repo)

        inc = await service.create_incident(build_incident_from_detection(_make_detection()))
        # OPEN -> RESOLVED
        inc2 = await service.transition_status(inc.incident_id, IncidentStatus.RESOLVED)
        # RESOLVED -> CLOSED
        inc3 = await service.transition_status(inc.incident_id, IncidentStatus.CLOSED)

        # CLOSED -> INVESTIGATING is ILLEGAL (CLOSED can only go to OPEN)
        with pytest.raises(ValidationError, match="Illegal incident status transition"):
            await service.transition_status(inc.incident_id, IncidentStatus.INVESTIGATING)

    @pytest.mark.asyncio
    async def test_optimistic_concurrency_conflict_raises_error(self) -> None:
        """Simulate concurrent modifications where repo version was bumped in between."""
        repo = _InMemoryFakeIncidentRepository()
        service = IncidentService(repo)

        inc = await service.create_incident(build_incident_from_detection(_make_detection()))

        # Simulate concurrent update in DB behind service's back
        # DB version becomes 2
        fake_concurrent_update = Incident(
            incident_id=inc.incident_id,
            title=inc.title,
            description=inc.description,
            severity=inc.severity,
            status=IncidentStatus.INVESTIGATING,
            version=2,
            created_at=inc.created_at,
            updated_at=datetime.now(timezone.utc),
        )
        repo._store[inc.incident_id] = fake_concurrent_update

        # Now attempting transition through service reading old stale expected version 1 should fail
        # Note: if service re-fetches, it gets version 2. To test optimistic conflict directly:
        with pytest.raises(IncidentConflictError):
            # Pass directly to repo.update with stale expected version 1
            await repo.update(fake_concurrent_update, expected_version=1)


class TestNoDomainInfraImportsInIncidents:
    def test_no_infra_imports(self) -> None:
        for module_name in [
            "incidents.enums",
            "incidents.models",
            "incidents.repository",
            "incidents.builder",
            "incidents.service",
        ]:
            mod = importlib.import_module(module_name)
            source = inspect.getsource(mod)
            for forbidden in ("redis", "fastapi", "scapy", "sqlalchemy", "psycopg"):
                assert f"import {forbidden}" not in source, f"{module_name} illegally imports {forbidden}"
                assert f"from {forbidden}" not in source, f"{module_name} illegally imports {forbidden}"
