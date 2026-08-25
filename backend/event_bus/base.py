"""
EventBus interfaces for SentinelX.

Defines the single canonical abstractions for event transport:
  - :class:`EventPublisher`: abstract publish interface
  - :class:`EventSubscriber`: abstract consume/ack interface
  - :class:`EventBus`: combined publisher and subscriber interface

These are pure-domain abstractions — no infrastructure imports allowed here.
"""

from __future__ import annotations

import abc
from typing import AsyncGenerator

from events.models import NormalizedEvent


class EventPublisher(abc.ABC):
    """Interface for components that publish normalised events."""

    @abc.abstractmethod
    async def publish(self, event: NormalizedEvent) -> None:
        """Publish a NormalizedEvent to the event transport."""


class EventSubscriber(abc.ABC):
    """Interface for components that consume normalised events."""

    @abc.abstractmethod
    async def consume(
        self,
        consumer_group: str,
        consumer_name: str,
    ) -> AsyncGenerator[tuple[str, NormalizedEvent], None]:
        """Yield (message_id, event) tuples from the transport.

        Must yield control (e.g. asyncio.sleep) on empty polls to avoid
        starving the asyncio event loop.
        """

    @abc.abstractmethod
    async def ack(
        self,
        consumer_group: str,
        message_id: str,
    ) -> None:
        """Acknowledge successful processing of a message."""


class EventBus(EventPublisher, EventSubscriber, abc.ABC):
    """Combined EventPublisher and EventSubscriber interface."""
