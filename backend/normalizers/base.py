"""
Normalizer abstraction for SentinelX.

Defines the single canonical :class:`BaseNormalizer` contract.  All
normalizers must implement this interface.  There is intentionally no
second normalizer abstraction anywhere in the codebase (architecture.md
§3, resolution #1 — nothing under ``events/normalizer.py``).

This module is pure-domain — no infrastructure imports.
"""

from __future__ import annotations

import abc

from events.models import NormalizedEvent
from sensors.base import RawEvent


class BaseNormalizer(abc.ABC):
    """Abstract base class for event normalizers.

    A normalizer converts a :class:`RawEvent` (produced by a sensor) into a
    :class:`NormalizedEvent` (the canonical domain event).

    Invariants
    ----------
    - Exactly ONE ``BaseNormalizer`` in the entire codebase.
    - Normalizers must never infer SSH_LOGIN or ARP_SPOOF — those require
      dedicated detection/correlation evidence.
    - TCP traffic → ``EventType.TCP``, ARP traffic → ``EventType.ARP_OBSERVED``.
    """

    @abc.abstractmethod
    def normalize(self, raw_event: RawEvent) -> NormalizedEvent:
        """Convert a RawEvent into a NormalizedEvent.

        Parameters
        ----------
        raw_event:
            The raw sensor observation.

        Returns
        -------
        NormalizedEvent:
            The normalised, immutable domain event.

        Raises
        ------
        NormalizationError:
            If the raw event cannot be normalised.
        """

    @abc.abstractmethod
    def can_handle(self, raw_event: RawEvent) -> bool:
        """Return True if this normalizer can handle the given raw event."""
