"""
Dependency Container for SentinelX — Single Composition Root.

Architecture Invariants:
- Single composition root in core/container.py.
- Explicit dependency injection.
- Zero module-level mutable singletons.
"""

from __future__ import annotations

import logging
from typing import Any

from core.config import Settings, get_settings
from correlation.engine import CorrelationEngine
from correlation.enums import Severity
from correlation.rule_runtime import DetectionRuleRuntimeManager
from correlation.rules.honeypot import HoneypotDetectionRule
from correlation.rules.port_scan import PortScanDetectionRule
from correlation.rules.ssh_bruteforce import SSHBruteForceDetectionRule
from correlation.sequence import DetectionSequenceRule, SequenceStage
from correlation.state import CorrelationStateStore, InMemoryCorrelationStateStore
from db.repositories.incident_repository import PostgresIncidentRepository
from db.repositories.rule_repository import PostgresDetectionRuleRepository
from db.repositories.user_repository import PostgresUserRepository
from db.session import DatabaseSessionManager
from event_bus.base import EventBus
from event_bus.redis_bus import RedisEventBus, create_redis_client
from events.persistence import LiveEventPersistenceHook
from incidents.repository import IncidentRepository
from incidents.service import IncidentService
from normalizers.factory import create_default_registry
from normalizers.registry import NormalizerRegistry
from pipeline.dispatcher import Dispatcher
from pipeline.pipeline import Pipeline
from sensors.manager import SensorManager
from sensors.scapy.sensor import ScapySensor
from vulnerabilities.live import LiveVulnerabilityCorrelationHook
from workers.correlation_worker import CorrelationWorker

logger = logging.getLogger(__name__)


class ApplicationContainer:
    """Dependency injection container holding all application components."""

    def __init__(
        self,
        settings: Settings | None = None,
        db_manager: DatabaseSessionManager | None = None,
        redis_bus: EventBus | None = None,
    ) -> None:
        self.settings: Settings = settings or get_settings()

        # Database
        self.db_manager: DatabaseSessionManager = (
            db_manager or DatabaseSessionManager(database_url=self.settings.DATABASE_URL)
        )
        self.db_manager.init()

        # Repositories
        self.incident_repository: IncidentRepository = PostgresIncidentRepository(
            self.db_manager.sessionmaker if self.db_manager else None  # type: ignore[arg-type]
        )
        self.rule_repository = PostgresDetectionRuleRepository(
            self.db_manager.sessionmaker if self.db_manager else None  # type: ignore[arg-type]
        )
        self.user_repository = PostgresUserRepository(
            self.db_manager.sessionmaker if self.db_manager else None  # type: ignore[arg-type]
        )

        # Incident Service
        self.incident_service = IncidentService(self.incident_repository)

        # Event Bus
        self.event_bus: EventBus | None = redis_bus

        # Standalone Redis client for auth concerns.
        self.redis_client: Any = create_redis_client(self.settings.REDIS_URL)

        # Normalization & Pipeline
        self.normalizer_registry: NormalizerRegistry = create_default_registry()
        self.dispatcher = Dispatcher(self.normalizer_registry)
        self.pipeline = Pipeline(
            dispatcher=self.dispatcher,
            publisher=self.event_bus,
        )

        # Sensor Manager & Default Sensor
        self.sensor_manager = SensorManager()
        self.scapy_sensor = ScapySensor(
            sensor_id="scapy-sensor-1",
            callback=self.pipeline.process,
            interface=self.settings.SNIFFER_INTERFACE,
            bpf_filter=self.settings.SNIFFER_FILTER,
        )
        self.sensor_manager.register(self.scapy_sensor)

        # Correlation State & Engine & Default Rules
        self.correlation_state_store: CorrelationStateStore = InMemoryCorrelationStateStore()
        self.correlation_engine = CorrelationEngine(
            state_store=self.correlation_state_store,
            rules=[
                PortScanDetectionRule(),
                SSHBruteForceDetectionRule(),
                HoneypotDetectionRule(),
            ],
            sequence_rules=[
                DetectionSequenceRule(
                    rule_id="RULE-ATTACK-CHAIN-01",
                    rule_name="Reconnaissance to SSH Attack Chain",
                    stages=[
                        SequenceStage(
                            rule_id="RULE-PORT-SCAN-01",
                            name="Network Service Scanning",
                            mitre_technique="T1046",
                        ),
                        SequenceStage(
                            rule_id="RULE-SSH-BRUTEFORCE-01",
                            name="Brute Force",
                            mitre_technique="T1110",
                        ),
                    ],
                    window_seconds=300.0,
                    severity=Severity.CRITICAL,
                    title="Reconnaissance followed by SSH attack activity",
                )
            ],
        )
        self.rule_runtime_manager = DetectionRuleRuntimeManager(self.correlation_engine)

        self.live_event_persistence_hook = LiveEventPersistenceHook(
            self.db_manager.sessionmaker
        )
        self.live_vulnerability_hook = LiveVulnerabilityCorrelationHook(
            self.db_manager.sessionmaker
        )

        # Correlation Worker
        self.correlation_worker: CorrelationWorker | None = None
        if self.event_bus is not None:
            self.correlation_worker = CorrelationWorker(
                subscriber=self.event_bus,
                engine=self.correlation_engine,
                incident_service=self.incident_service,
                event_persist_hook=self.live_event_persistence_hook,
                post_event_hook=self.live_vulnerability_hook,
            )

    async def refresh_detection_rules(self) -> dict[str, int]:
        """Load persisted detection rules and apply them to the live engine."""
        rules = await self.rule_repository.list_rules(limit=1000, offset=0)
        return self.rule_runtime_manager.apply_rules(rules)

    def attach_redis_bus(self, event_bus: EventBus) -> None:
        """Attach Redis event bus after async initialization."""
        self.event_bus = event_bus
        self.pipeline = Pipeline(dispatcher=self.dispatcher, publisher=event_bus)
        self.correlation_worker = CorrelationWorker(
            subscriber=event_bus,
            engine=self.correlation_engine,
            incident_service=self.incident_service,
            event_persist_hook=self.live_event_persistence_hook,
            post_event_hook=self.live_vulnerability_hook,
        )
