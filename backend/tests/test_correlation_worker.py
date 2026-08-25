"""Unit tests for Phase 11 CorrelationWorker."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import AsyncGenerator
import pytest

from correlation.engine import CorrelationEngine
from correlation.rules.port_scan import PortScanDetectionRule
from correlation.state import InMemoryCorrelationStateStore
from event_bus.base import EventSubscriber
from events.models import NormalizedEvent
from incidents.builder import build_incident_from_detection
from incidents.enums import IncidentStatus
from incidents.models import Incident
from incidents.repository import IncidentRepository
from incidents.service import IncidentService
from workers.correlation_worker import CorrelationWorker


class StubSubscriber(EventSubscriber):
    def __init__(self, events: list[tuple[str, NormalizedEvent]]) -> None:
        self._events = events
        self.acked_ids: list[str] = []

    async def consume(
        self, consumer_group: str, consumer_name: str
    ) -> AsyncGenerator[tuple[str, NormalizedEvent], None]:
        for msg_id, event in self._events:
            yield msg_id, event
            await asyncio.sleep(0.01)

    async def ack(self, consumer_group: str, message_id: str) -> None:
        self.acked_ids.append(message_id)


class StubIncidentRepository(IncidentRepository):
    def __init__(self) -> None:
        self.incidents: list[Incident] = []

    async def create(self, incident: Incident) -> Incident:
        self.incidents.append(incident)
        return incident

    async def get_by_id(self, incident_id: str) -> Incident | None:
        return next((i for i in self.incidents if i.incident_id == incident_id), None)

    async def update(self, incident: Incident, expected_version: int) -> Incident:
        return incident

    async def list_all(self, limit: int = 100, offset: int = 0) -> list[Incident]:
        return self.incidents


def _make_event(msg_id: str, dport: int) -> tuple[str, NormalizedEvent]:
    event = NormalizedEvent(
        event_type="TCP",
        timestamp=datetime.now(timezone.utc),
        sensor_id="sensor-1",
        source_ip="10.0.0.99",
        destination_ip="192.168.1.1",
        destination_port=dport,
        protocol="TCP",
    )
    return msg_id, event


class TestCorrelationWorker:
    @pytest.mark.asyncio
    async def test_worker_end_to_end_detection_and_incident(self) -> None:
        # Prepare 3 distinct port scan events
        events = [
            _make_event("msg-1", 80),
            _make_event("msg-2", 443),
            _make_event("msg-3", 22),
        ]
        subscriber = StubSubscriber(events)

        store = InMemoryCorrelationStateStore()
        rule = PortScanDetectionRule(distinct_ports_threshold=3, window_seconds=60)
        engine = CorrelationEngine(store, [rule])

        repo = StubIncidentRepository()
        service = IncidentService(repo)

        worker = CorrelationWorker(
            subscriber=subscriber,
            engine=engine,
            incident_service=service,
        )

        await worker.start()
        await asyncio.sleep(0.1)
        await worker.stop()

        health = worker.get_health()
        assert health["events_processed"] == 3
        assert health["detections_count"] == 1
        assert health["incidents_created"] == 1
        assert len(repo.incidents) == 1
        assert repo.incidents[0].source_ip == "10.0.0.99"
        assert subscriber.acked_ids == ["msg-1", "msg-2", "msg-3"]

    @pytest.mark.asyncio
    async def test_worker_error_isolation(self) -> None:
        """Failing event processing does not crash the worker loop."""
        events = [_make_event("msg-1", 80)]
        subscriber = StubSubscriber(events)

        store = InMemoryCorrelationStateStore()
        engine = CorrelationEngine(store)

        class FailingRepo(StubIncidentRepository):
            async def create(self, incident: Incident) -> Incident:
                raise RuntimeError("Database write error")

        rule = PortScanDetectionRule(distinct_ports_threshold=1, window_seconds=60)
        engine.register_rule(rule)

        service = IncidentService(FailingRepo())

        worker = CorrelationWorker(
            subscriber=subscriber,
            engine=engine,
            incident_service=service,
        )

        await worker.start()
        await asyncio.sleep(0.05)
        await worker.stop()

        health = worker.get_health()
        assert health["failures_count"] == 1
        assert "Database write error" in (health["last_error"] or "")
