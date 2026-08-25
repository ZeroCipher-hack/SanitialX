"""
Sensor abstraction layer for SentinelX.

Defines :class:`BaseSensor` (the single canonical sensor interface) and
the :class:`RawEvent` type that sensors produce.

This module is pure-domain — it defines the contract, not the implementation.
Infrastructure-specific sensors (Scapy, etc.) live in sub-packages and
import this base.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine


@dataclass(frozen=True)
class RawEvent:
    """Raw observation emitted by a sensor before normalisation.

    This is a lightweight, immutable data carrier — it holds just enough
    metadata for the normaliser to produce a :class:`NormalizedEvent`.
    No payload retention beyond what's needed for metadata extraction.
    """

    sensor_id: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    raw_data: dict[str, Any] = field(default_factory=dict)


# Type alias for the async callback that receives raw events.
RawEventCallback = Callable[[RawEvent], Coroutine[Any, Any, None]]


class BaseSensor(abc.ABC):
    """Abstract base class for all SentinelX sensors.

    Subclasses must implement ``start``, ``stop``, and ``is_running``.
    When a sensor captures data, it must invoke the registered callback
    with a :class:`RawEvent`.

    Invariants
    ----------
    - Exactly one ``BaseSensor`` contract in the codebase.
    - Sensors must not fabricate information beyond what they can observe
      (architecture.md invariant #10).
    - Health counters must be thread-safe (architecture.md invariant #3).
    """

    def __init__(self, sensor_id: str, callback: RawEventCallback) -> None:
        self._sensor_id = sensor_id
        self._callback = callback

    @property
    def sensor_id(self) -> str:
        return self._sensor_id

    @abc.abstractmethod
    async def start(self) -> None:
        """Start the sensor. Must capture the running event loop for
        thread→asyncio bridging if needed."""

    @abc.abstractmethod
    async def stop(self) -> None:
        """Stop the sensor gracefully."""

    @abc.abstractmethod
    def is_running(self) -> bool:
        """Return whether the sensor is currently active."""

    @abc.abstractmethod
    def health(self) -> dict[str, Any]:
        """Return health/stats counters.

        Must include at least:
        - running: bool
        - packets_captured: int
        - errors: int
        - last_error: str | None
        """
