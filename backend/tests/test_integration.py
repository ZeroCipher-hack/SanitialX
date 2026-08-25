"""
Phase 16 — Integration Tests for SentinelX.

Coverage:
1. EventBus publishing and consumption round-trip semantics.
2. IncidentRepository and DetectionRuleRepository ORM persistence against full schema.
3. Pipeline → EventBus stream publishing flow.
4. CorrelationWorker → CorrelationEngine → IncidentRepository end-to-end integration loop.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import AsyncGenerator
import pytest

from correlation.engine import CorrelationEngine
from correlation.enums import Severity
from correlation.rules.port_scan import PortScanDetectionRule
from correlation.state import InMemoryCorrelationStateStore
from db.base import Base
from db.repositories.incident_repository import PostgresIncidentRepository
from db.repositories.rule_repository import PostgresDetectionRuleRepository
from db.session import DatabaseSessionManager
from event_bus.base import EventBus, EventPublisher, EventSubscriber
from events.models import NormalizedEvent
from incidents.enums import IncidentStatus
from incidents.models import Incident
from incidents.service import IncidentService
from normalizers.factory import create_default_registry
from pipeline.dispatcher import Dispatcher
from pipeline.pipeline import Pipeline
from sensors.base import RawEvent
from workers.correlation_worker import CorrelationWorker


class InMemoryEventBus(EventBus):
    """In-memory event bus simulating Redis Stream consumer groups for test suite execution."""

    def __init__(self) -> None:
        self._stream: list[tuple[str, NormalizedEvent]] = []
        self._acked: set[str] = set()
        self._counter = 0

    async def publish(self, event: NormalizedEvent) -> None:
        self._counter += 1
        msg_id = f"1000000000000-{self._counter}"
        self._stream.append((msg_id, event))

    async def consume(
        self, consumer_group: str = "test-group", consumer_name: str | None = None
    ) -> AsyncGenerator[tuple[str, NormalizedEvent], None]:
        for msg_id, event in self._stream:
            yield msg_id, event
            await asyncio.sleep(0.001)

    async def ack(self, consumer_group: str = "test-group", message_id: str = "") -> None:
        self._acked.add(message_id)


@pytest.fixture
async def async_db():
    db_mgr = DatabaseSessionManager("sqlite+aiosqlite:///:memory:")
    db_mgr.init()
    async with db_mgr._engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield db_mgr
    await db_mgr.close()


class TestIntegration:
    @pytest.mark.asyncio
    async def test_event_bus_publish_consume_roundtrip(self) -> None:
        bus = InMemoryEventBus()
        event = NormalizedEvent(
            event_type="TCP",
            timestamp=datetime.now(timezone.utc),
            sensor_id="sensor-int-1",
            source_ip="192.168.1.50",
            destination_ip="10.0.0.1",
            destination_port=80,
            protocol="TCP",
        )

        await bus.publish(event)
        assert len(bus._stream) == 1

        async for msg_id, consumed_event in bus.consume():
            assert consumed_event.event_id == event.event_id
            assert consumed_event.source_ip == "192.168.1.50"
            await bus.ack(message_id=msg_id)
            break

        assert len(bus._acked) == 1

    @pytest.mark.asyncio
    async def test_repositories_orm_persistence(self, async_db: DatabaseSessionManager) -> None:
        inc_repo = PostgresIncidentRepository(async_db.sessionmaker)
        rule_repo = PostgresDetectionRuleRepository(async_db.sessionmaker)

        # 1. Test Rule persistence
        await rule_repo.save_rule(
            rule_id="R-INT-1",
            rule_name="Integration Rule",
            severity="HIGH",
            description="Integration rule desc",
            enabled=True,
            parameters={"threshold": 5},
        )
        saved_rule = await rule_repo.get_rule("R-INT-1")
        assert saved_rule is not None
        assert saved_rule["rule_name"] == "Integration Rule"

        # 2. Test Incident persistence with optimistic concurrency version check
        inc = Incident(
            incident_id="INC-INT-100",
            title="Integration Incident",
            description="Testing DB persistence",
            severity=Severity.HIGH,
            status=IncidentStatus.OPEN,
            version=1,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
            source_ip="10.0.0.5",
        )
        created = await inc_repo.create(inc)
        assert created.version == 1

        retrieved = await inc_repo.get_by_id("INC-INT-100")
        assert retrieved is not None
        assert retrieved.title == "Integration Incident"

    @pytest.mark.asyncio
    async def test_pipeline_to_event_bus_flow(self) -> None:
        bus = InMemoryEventBus()
        registry = create_default_registry()
        dispatcher = Dispatcher(registry)
        pipeline = Pipeline(dispatcher=dispatcher, publisher=bus)

        raw_event = RawEvent(
            sensor_id="sensor-scapy-1",
            timestamp=datetime.now(timezone.utc),
            raw_data={
                "source_ip": "172.16.0.10",
                "destination_ip": "172.16.0.20",
                "protocol": "TCP",
                "source_port": 12345,
                "destination_port": 443,
            },
        )

        norm_event = await pipeline.process(raw_event)
        assert norm_event is not None
        assert norm_event.source_ip == "172.16.0.10"
        assert len(bus._stream) == 1

    @pytest.mark.asyncio
    async def test_correlation_worker_consume_correlate_persist_loop(
        self, async_db: DatabaseSessionManager
    ) -> None:
        bus = InMemoryEventBus()
        inc_repo = PostgresIncidentRepository(async_db.sessionmaker)
        inc_service = IncidentService(inc_repo)

        # Register PortScan rule (threshold = 3)
        rule = PortScanDetectionRule(distinct_ports_threshold=3, window_seconds=60)
        state_store = InMemoryCorrelationStateStore()
        engine = CorrelationEngine(state_store=state_store, rules=[rule])

        worker = CorrelationWorker(
            subscriber=bus,
            engine=engine,
            incident_service=inc_service,
        )

        # Publish 3 port scan events targeting different ports from same source IP
        for port in [80, 443, 8080]:
            event = NormalizedEvent(
                event_type="TCP",
                timestamp=datetime.now(timezone.utc),
                sensor_id="sensor-scan",
                source_ip="192.168.1.200",
                destination_ip="10.0.0.1",
                destination_port=port,
                protocol="TCP",
            )
            await bus.publish(event)

        # Run worker loop briefly
        await worker.start()
        await asyncio.sleep(0.15)
        await worker.stop()

        # Assert incident was automatically generated and persisted in DB
        incidents = await inc_repo.list_all()
        assert len(incidents) == 1
        assert incidents[0].source_ip == "192.168.1.200"
        assert incidents[0].status == IncidentStatus.OPEN
