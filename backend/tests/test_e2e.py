"""
Phase 17 — Full End-to-End (E2E) Tests for SentinelX.

Coverage:
1. Full Pipeline Chain:
   Real Scapy Packet objects → ScapySensor (tested with real OS thread bridge) → Dispatcher →
   ScapyNormalizer → Pipeline → EventBus → CorrelationWorker → CorrelationEngine →
   DetectionRule → IncidentService → Database Repository.
2. Optimistic Concurrency Collision Test:
   Reproduce a race between a worker update and a direct analyst update on the exact
   same incident version. Assert the losing writer gets IncidentConflictError.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import threading
import pytest
from scapy.layers.inet import IP, TCP  # type: ignore[import-untyped]

from correlation.engine import CorrelationEngine
from correlation.enums import Severity
from correlation.rules.port_scan import PortScanDetectionRule
from correlation.state import InMemoryCorrelationStateStore
from core.errors import IncidentConflictError
from db.base import Base
from db.repositories.incident_repository import PostgresIncidentRepository
from db.session import DatabaseSessionManager
from event_bus.base import EventBus
from events.models import NormalizedEvent
from incidents.enums import IncidentStatus
from incidents.models import Incident
from incidents.service import IncidentService
from normalizers.factory import create_default_registry
from pipeline.dispatcher import Dispatcher
from pipeline.pipeline import Pipeline
from sensors.scapy.sensor import ScapySensor
from workers.correlation_worker import CorrelationWorker


class E2EEventBus(EventBus):
    """EventBus implementation for E2E stream processing."""

    def __init__(self) -> None:
        self._stream: list[tuple[str, NormalizedEvent]] = []
        self._counter = 0
        self.acked_ids: list[str] = []

    async def publish(self, event: NormalizedEvent) -> None:
        self._counter += 1
        msg_id = f"1000000000000-{self._counter}"
        self._stream.append((msg_id, event))

    async def consume(
        self, consumer_group: str = "e2e-group", consumer_name: str | None = None
    ):
        for msg_id, event in self._stream:
            yield msg_id, event
            await asyncio.sleep(0.001)

    async def ack(self, consumer_group: str = "e2e-group", message_id: str = "") -> None:
        self.acked_ids.append(message_id)


@pytest.fixture
async def async_db():
    db_mgr = DatabaseSessionManager("sqlite+aiosqlite:///:memory:")
    db_mgr.init()
    async with db_mgr._engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield db_mgr
    await db_mgr.close()


class TestEndToEnd:
    @pytest.mark.asyncio
    async def test_full_e2e_packet_to_persisted_incident_chain(
        self, async_db: DatabaseSessionManager
    ) -> None:
        """Full data pipeline execution with real Scapy packets and real OS thread callback bridge."""
        event_bus = E2EEventBus()
        registry = create_default_registry()
        dispatcher = Dispatcher(registry)
        pipeline = Pipeline(dispatcher=dispatcher, publisher=event_bus)

        # 1. Instantiate ScapySensor
        sensor = ScapySensor(
            sensor_id="e2e-sensor-1",
            callback=pipeline.process,
        )
        sensor._loop = asyncio.get_running_loop()
        sensor._running = True

        # 2. Setup Correlation Engine with PortScan detection rule (threshold = 3)
        state_store = InMemoryCorrelationStateStore()
        rule = PortScanDetectionRule(distinct_ports_threshold=3, window_seconds=60)
        engine = CorrelationEngine(state_store=state_store, rules=[rule])

        # 3. Setup Incident Service & DB Repository
        inc_repo = PostgresIncidentRepository(async_db.sessionmaker)
        inc_service = IncidentService(inc_repo)

        # 4. Setup CorrelationWorker
        worker = CorrelationWorker(
            subscriber=event_bus,
            engine=engine,
            incident_service=inc_service,
        )

        # 5. Inject 3 distinct TCP Scapy Packet objects from a REAL separate OS thread to verify thread-to-async bridge
        scapy_packets = [
            IP(src="10.99.0.5", dst="192.168.1.1") / TCP(sport=10000 + i, dport=target_port)
            for i, target_port in enumerate([21, 22, 80])
        ]

        def thread_packet_producer():
            for pkt in scapy_packets:
                sensor._on_packet(pkt)

        producer_thread = threading.Thread(target=thread_packet_producer)
        producer_thread.start()
        producer_thread.join()

        # Give asyncio loop time to execute threadsafe scheduled coroutines
        await asyncio.sleep(0.1)

        sensor._running = False

        # Verify events were normalized and published to stream
        assert len(event_bus._stream) == 3

        # 6. Run CorrelationWorker to consume stream events and generate incident
        await worker.start()
        await asyncio.sleep(0.15)
        await worker.stop()

        # 7. Assert Incident was persisted in DB repository
        incidents = await inc_repo.list_all()
        assert len(incidents) == 1
        created_inc = incidents[0]
        assert created_inc.source_ip == "10.99.0.5"
        assert created_inc.status == IncidentStatus.OPEN
        assert created_inc.version == 1

    @pytest.mark.asyncio
    async def test_optimistic_concurrency_race_condition(
        self, async_db: DatabaseSessionManager
    ) -> None:
        """Simulate worker and analyst concurrent updates racing on the same incident.

        Asserts that the losing writer receives IncidentConflictError instead of silently overwriting.
        """
        inc_repo = PostgresIncidentRepository(async_db.sessionmaker)
        service = IncidentService(inc_repo)

        # 1. Create initial incident (version = 1)
        initial_inc = Incident(
            incident_id="INC-RACE-001",
            title="Suspicious Activity",
            description="Initial detection",
            severity=Severity.HIGH,
            status=IncidentStatus.OPEN,
            version=1,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            source_ip="10.0.0.99",
        )
        await inc_repo.create(initial_inc)

        # 2. Both Analyst and Worker fetch incident at version 1
        analyst_view = await service.get_incident("INC-RACE-001")
        worker_view = await service.get_incident("INC-RACE-001")

        assert analyst_view is not None and worker_view is not None
        assert analyst_view.version == 1
        assert worker_view.version == 1

        # 3. Analyst successfully updates incident status: OPEN -> INVESTIGATING
        # Version advances to 2 in database
        updated_by_analyst = await service.transition_status("INC-RACE-001", IncidentStatus.INVESTIGATING)
        assert updated_by_analyst.version == 2

        # 4. Worker (holding stale version = 1) attempts to update the incident status or save changes
        stale_incident_update = Incident(
            incident_id=worker_view.incident_id,
            title=worker_view.title,
            description="Worker added contextual notes",
            severity=worker_view.severity,
            status=IncidentStatus.CLOSED,
            version=2,  # Trying to save with next expected version = 1 + 1 = 2
            created_at=worker_view.created_at,
            updated_at=datetime.now(timezone.utc),
            source_ip=worker_view.source_ip,
        )

        # Attaching expected_version = 1 (stale version held by worker)
        with pytest.raises(IncidentConflictError) as exc_info:
            await inc_repo.update(stale_incident_update, expected_version=1)

        assert "INC-RACE-001" in str(exc_info.value)

        # 5. Confirm DB state remains as updated by the winning writer (Analyst: INVESTIGATING, version = 2)
        db_final = await inc_repo.get_by_id("INC-RACE-001")
        assert db_final is not None
        assert db_final.status == IncidentStatus.INVESTIGATING
        assert db_final.version == 2
