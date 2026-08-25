"""
Event processing pipeline for SentinelX.

Orchestrates the full raw-event-to-published-event flow:
  raw → normalise (via Dispatcher) → validate → publish → record stats

The pipeline depends on an :class:`EventPublisher` protocol for the publish
step.  The concrete implementation (Redis Streams) is Phase 7 — for now the
pipeline accepts any object satisfying the protocol.  If no publisher is
provided, events are normalised and validated but not published (useful for
testing and early phases).

Malformed-event failures are **isolated** — they are logged and counted but
must never crash the pipeline.
"""

from __future__ import annotations

import abc
import logging
import threading
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from core.errors import NormalizationError, PipelineError
from events.models import NormalizedEvent
from pipeline.dispatcher import Dispatcher
from sensors.base import RawEvent

logger = logging.getLogger(__name__)


from event_bus.base import EventPublisher



# ── Pipeline stats ────────────────────────────────────────────────────────

@dataclass
class PipelineStats:
    """Thread-safe pipeline processing statistics.

    All mutations go through :meth:`increment_*` methods which acquire
    the internal lock.
    """

    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    events_received: int = 0
    events_normalised: int = 0
    events_published: int = 0
    events_failed: int = 0
    last_error: str | None = None

    def increment_received(self) -> None:
        with self._lock:
            self.events_received += 1

    def increment_normalised(self) -> None:
        with self._lock:
            self.events_normalised += 1

    def increment_published(self) -> None:
        with self._lock:
            self.events_published += 1

    def record_failure(self, error: str) -> None:
        with self._lock:
            self.events_failed += 1
            self.last_error = error

    def snapshot(self) -> dict[str, Any]:
        """Return a point-in-time copy of stats."""
        with self._lock:
            return {
                "events_received": self.events_received,
                "events_normalised": self.events_normalised,
                "events_published": self.events_published,
                "events_failed": self.events_failed,
                "last_error": self.last_error,
            }


# ── Pipeline ──────────────────────────────────────────────────────────────

class Pipeline:
    """Core event-processing pipeline.

    Workflow per event::

        receive(raw_event)
          ├─ dispatcher.dispatch(raw_event)   → NormalizedEvent
          ├─ validate event (Pydantic already enforced at construction)
          ├─ publisher.publish(event)          → (Phase 7+)
          └─ record stats

    Any failure in a single event is **isolated**: the error is logged and
    the ``events_failed`` counter incremented, but the pipeline continues
    processing subsequent events.

    Parameters
    ----------
    dispatcher:
        The Dispatcher that routes raw events to normalizers.
    publisher:
        Optional EventPublisher.  If ``None``, events are normalised and
        validated but not published (Phase 7 wires the real publisher).
    """

    def __init__(
        self,
        dispatcher: Dispatcher,
        publisher: EventPublisher | None = None,
    ) -> None:
        self._dispatcher = dispatcher
        self._publisher = publisher
        self._stats = PipelineStats()

    @property
    def stats(self) -> PipelineStats:
        return self._stats

    async def process(self, raw_event: RawEvent) -> NormalizedEvent | None:
        """Process a single raw event through the full pipeline.

        Returns the NormalizedEvent on success, or ``None`` if the event
        could not be processed (failure is logged, not raised).
        """
        self._stats.increment_received()

        try:
            # Step 1: Normalise
            event = self._dispatcher.dispatch(raw_event)
            self._stats.increment_normalised()

            # Step 2: Validate (NormalizedEvent is Pydantic — construction
            # already validates.  We assert the invariants hold here.)
            self._validate(event)

            # Step 3: Publish (if publisher is wired)
            if self._publisher is not None:
                await self._publisher.publish(event)
            self._stats.increment_published()

            logger.debug(
                "Pipeline processed event %s (type=%s)",
                event.event_id,
                event.event_type,
            )
            return event

        except Exception as exc:  # noqa: BLE001
            # Isolate failures — must NEVER crash the pipeline
            error_msg = f"{type(exc).__name__}: {exc}"
            self._stats.record_failure(error_msg)
            logger.warning(
                "Pipeline failed to process event from sensor '%s': %s",
                raw_event.sensor_id,
                error_msg,
            )
            return None

    @staticmethod
    def _validate(event: NormalizedEvent) -> None:
        """Post-normalisation validation.

        NormalizedEvent construction already enforces Pydantic validation
        (UTC-aware timestamp, required fields, etc.).  This method provides
        a hook for additional domain-level checks if needed in the future.

        Raises
        ------
        PipelineError
            If any post-normalisation invariant is violated.
        """
        if event.timestamp.tzinfo is None:
            raise PipelineError(
                f"Event {event.event_id} has a naive timestamp after normalisation"
            )
