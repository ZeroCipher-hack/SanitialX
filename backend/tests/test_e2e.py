"""
Phase 17 — Full End-to-End (E2E) Tests for SanitialX.

Coverage:
1. Full Pipeline Chain:
   Real Scapy Packet objects → ScapySensor → Dispatcher → ScapyNormalizer → Pipeline →
   EventBus → CorrelationWorker → CorrelationEngine → DetectionRule → IncidentService → DB →
   analyst-approved SOAR → endpoint command completion → professional report rendering.
2. Optimistic Concurrency Collision Test.
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
from db.models.agent import AgentModel
from db.repositories.incident_repository import PostgresIncidentRepository
from db.repositories.soar_repository import PostgresSoarRepository
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
from services.ai_analysis import fallback_analysis
from services.report_renderer import render_incident_report
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

    async def consume(self, consumer_group: str = "e2e-group", consumer_name: str | None = None):
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
    async def test_full_v1_packet_to_report_chain(self, async_db: DatabaseSessionManager) -> None:
        """Prove the v1 defensive chain from packet telemetry through analyst-approved response and report."""
        event_bus = E2EEventBus()
        pipeline = Pipeline(dispatcher=Dispatcher(create_default_registry()), publisher=event_bus)
        sensor = ScapySensor(sensor_id="e2e-sensor-1", callback=pipeline.process)
        sensor._loop = asyncio.get_running_loop()
        sensor._running = True

        engine = CorrelationEngine(
            state_store=InMemoryCorrelationStateStore(),
            rules=[PortScanDetectionRule(distinct_ports_threshold=3, window_seconds=60)],
        )
        inc_repo = PostgresIncidentRepository(async_db.sessionmaker)
        worker = CorrelationWorker(
            subscriber=event_bus,
            engine=engine,
            incident_service=IncidentService(inc_repo),
        )

        packets = [
            IP(src="10.99.0.5", dst="192.168.1.1") / TCP(sport=10000 + i, dport=port)
            for i, port in enumerate([21, 22, 80])
        ]

        def producer():
            for packet in packets:
                sensor._on_packet(packet)

        thread = threading.Thread(target=producer)
        thread.start(); thread.join()
        await asyncio.sleep(0.1)
        sensor._running = False
        assert len(event_bus._stream) == 3

        await worker.start(); await asyncio.sleep(0.15); await worker.stop()
        incidents = await inc_repo.list_all()
        assert len(incidents) == 1
        incident = incidents[0]
        assert incident.source_ip == "10.99.0.5"
        assert incident.status == IncidentStatus.OPEN

        # Endpoint/asset + analyst approval + safe read-only command lifecycle.
        async with async_db.sessionmaker() as session:
            agent = AgentModel(
                agent_id="e2e-agent", hostname="target.local", ip_address="192.168.1.1",
                os="Linux", status="ONLINE", lifecycle_status="MANAGED", agent_token_hash="b" * 64,
            )
            session.add(agent); await session.commit()
            soar = PostgresSoarRepository(session)
            action = await soar.create_action({
                "incident_id": incident.incident_id,
                "action_type": "COLLECT_FORENSICS",
                "target_type": "ASSET",
                "target_value": agent.agent_id,
                "parameters": {},
                "risk_level": "LOW",
                "reason": "Collect read-only endpoint evidence for the investigation.",
            }, actor="e2e-analyst")
            assert action.status == "PENDING"
            action = await soar.decide(action, approve=True, actor="e2e-analyst", note="E2E approved")
            command = await soar.queue_agent_command(
                action,
                agent_id=agent.agent_id,
                command_type="COLLECT_SYSTEM_INFO",
                payload={"incident_id": incident.incident_id},
                actor="e2e-analyst",
            )
            command = await soar.claim_agent_command(command)
            await soar.complete_agent_command(command, result={
                "ok": True,
                "message": "Read-only system information collected.",
                "data": {"hostname": agent.hostname, "platform": "Linux"},
            })
            final_action = await soar.get(action.action_id)
            audit = await soar.audit(action.action_id)

        assert final_action is not None and final_action.status == "EXECUTED"
        assert [item.event for item in audit] == ["REQUESTED", "APPROVED", "COMMAND_QUEUED", "COMPLETED"]

        # AI contract (deterministic fallback in CI) + professional report rendering.
        analysis = fallback_analysis(incident)
        html = render_incident_report(
            {
                "report_id": f"REP-{incident.incident_id}",
                "incident_id": incident.incident_id,
                "title": incident.title,
                "severity": incident.severity.value,
                "status": incident.status.value,
                "created_at": incident.created_at.isoformat(),
                "updated_at": incident.updated_at.isoformat(),
                "source_ip": incident.source_ip,
                "destination_ip": incident.destination_ip,
                "triggering_detection_ids": incident.triggering_detection_ids,
                **analysis.model_dump(),
            },
            soar_actions=[{
                "action_type": final_action.action_type,
                "target_value": final_action.target_value,
                "status": final_action.status,
                "approved_by": final_action.approved_by,
                "rejected_by": final_action.rejected_by,
            }],
            timeline=[{
                "timestamp": item.created_at.isoformat(),
                "event": item.event,
                "actor": item.actor,
                "details": item.details,
            } for item in audit],
        )
        assert "Incident Investigation Report" in html
        assert incident.incident_id in html
        assert "COLLECT_FORENSICS" in html
        assert "COMPLETED" in html
        assert "Recommended Remediation" in html

    @pytest.mark.asyncio
    async def test_optimistic_concurrency_race_condition(self, async_db: DatabaseSessionManager) -> None:
        inc_repo = PostgresIncidentRepository(async_db.sessionmaker)
        service = IncidentService(inc_repo)
        initial_inc = Incident(
            incident_id="INC-RACE-001", title="Suspicious Activity", description="Initial detection",
            severity=Severity.HIGH, status=IncidentStatus.OPEN, version=1,
            created_at=datetime.now(timezone.utc), updated_at=datetime.now(timezone.utc), source_ip="10.0.0.99",
        )
        await inc_repo.create(initial_inc)
        analyst_view = await service.get_incident("INC-RACE-001")
        worker_view = await service.get_incident("INC-RACE-001")
        assert analyst_view is not None and worker_view is not None
        updated = await service.transition_status("INC-RACE-001", IncidentStatus.INVESTIGATING)
        assert updated.version == 2
        stale = Incident(
            incident_id=worker_view.incident_id, title=worker_view.title,
            description="Worker added contextual notes", severity=worker_view.severity,
            status=IncidentStatus.CLOSED, version=2, created_at=worker_view.created_at,
            updated_at=datetime.now(timezone.utc), source_ip=worker_view.source_ip,
        )
        with pytest.raises(IncidentConflictError):
            await inc_repo.update(stale, expected_version=1)
        db_final = await inc_repo.get_by_id("INC-RACE-001")
        assert db_final is not None
        assert db_final.status == IncidentStatus.INVESTIGATING
        assert db_final.version == 2
