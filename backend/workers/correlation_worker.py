"""
CorrelationWorker — background worker consuming events and driving detection & incident creation.

Requirements:
- Consumes NormalizedEvents from EventSubscriber.
- Passes events to CorrelationEngine.
- On Detection, uses build_incident_from_detection and IncidentService to create incidents.
- ACKs processed messages via EventSubscriber.ack.
- Lifecycle: start(), stop(), cancellation handling.
- Per-event error isolation (one bad event does not kill worker loop).
- Health status distinguishing running vs successfully_processing.
- Separate counters for processed events and failures.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any

from correlation.engine import CorrelationEngine
from event_bus.base import EventSubscriber
from incidents.builder import build_incident_from_detection
from incidents.service import IncidentService

logger = logging.getLogger(__name__)


class CorrelationWorker:
    """Async background worker for event correlation and incident generation."""

    def __init__(

        self,
        subscriber: EventSubscriber,
        engine: CorrelationEngine,
        incident_service: IncidentService,
        consumer_group: str = "sentinelx-consumers",
        consumer_name: str = "correlation-worker-1",
    ) -> None:
        self._subscriber = subscriber
        self._engine = engine
        self._incident_service = incident_service
        self._consumer_group = consumer_group
        self._consumer_name = consumer_name

        self._task: asyncio.Task[None] | None = None
        self._running = False
        self._lock = threading.Lock()

        # Metrics
        self._events_processed = 0
        self._detections_count = 0
        self._incidents_created = 0
        self._failures_count = 0
        self._last_error: str | None = None

    @property
    def is_running(self) -> bool:
        return self._running

    def get_health(self) -> dict[str, Any]:
        """Return health status and processing metrics."""
        with self._lock:
            return {
                "running": self._running,
                "successfully_processing": self._running and self._failures_count == 0,
                "events_processed": self._events_processed,
                "detections_count": self._detections_count,
                "incidents_created": self._incidents_created,
                "failures_count": self._failures_count,
                "last_error": self._last_error,
            }

    async def start(self) -> None:
        """Start the background worker consumption loop."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._run_loop(), name="CorrelationWorker")
        logger.info("CorrelationWorker started.")

    async def stop(self) -> None:
        """Stop the background worker gracefully."""
        if not self._running:
            return
        self._running = False
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        logger.info("CorrelationWorker stopped.")

    async def _run_loop(self) -> None:
        try:
            async for msg_id, event in self._subscriber.consume(
                consumer_group=self._consumer_group,
                consumer_name=self._consumer_name,
            ):
                if not self._running:
                    break

                try:
                    # 1. Process event through correlation engine
                    detections = self._engine.process_event(event)

                    with self._lock:
                        self._events_processed += 1
                        self._detections_count += len(detections)

                    # 2. For each detection, build and create incident
                    for detection in detections:
                        incident = build_incident_from_detection(detection)
                        await self._incident_service.create_incident(incident)
                        with self._lock:
                            self._incidents_created += 1

                    # 3. ACK message
                    await self._subscriber.ack(self._consumer_group, msg_id)

                except Exception as exc:
                    error_msg = f"{type(exc).__name__}: {exc}"
                    logger.error(
                        "CorrelationWorker error processing msg %s: %s",
                        msg_id,
                        error_msg,
                    )
                    with self._lock:
                        self._failures_count += 1
                        self._last_error = error_msg
                    # Failure isolated — worker loop continues

        except asyncio.CancelledError:
            logger.info("CorrelationWorker task cancelled.")
            raise
        except Exception as fatal_exc:
            logger.critical("CorrelationWorker loop died unexpectedly: %s", fatal_exc)
            with self._lock:
                self._running = False
                self._last_error = str(fatal_exc)
