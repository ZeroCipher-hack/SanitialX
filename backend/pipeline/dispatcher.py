"""
Dispatcher — routes RawEvents to the appropriate normalizer.

Sits between sensors and the pipeline.  When a sensor produces a RawEvent,
the dispatcher finds the correct normalizer (via the NormalizerRegistry)
and invokes it.  It then forwards the resulting NormalizedEvent to the
pipeline for validation, publishing, and stats recording.
"""

from __future__ import annotations

import logging
from typing import Any

from core.errors import NormalizationError
from events.models import NormalizedEvent
from normalizers.registry import NormalizerRegistry
from sensors.base import RawEvent

logger = logging.getLogger(__name__)


class Dispatcher:
    """Routes raw events through the normalizer registry.

    The dispatcher is responsible for:
    1. Finding the correct normalizer for a given RawEvent.
    2. Invoking normalisation.
    3. Returning the NormalizedEvent (or raising on failure).

    It does NOT own the publish step — that belongs to the Pipeline.
    """

    def __init__(self, registry: NormalizerRegistry) -> None:
        self._registry = registry

    def dispatch(self, raw_event: RawEvent) -> NormalizedEvent:
        """Normalise a RawEvent.

        Parameters
        ----------
        raw_event:
            The raw sensor observation.

        Returns
        -------
        NormalizedEvent

        Raises
        ------
        NormalizationError
            If no normalizer can handle the event, or normalisation itself fails.
        """
        normalizer = self._registry.get_normalizer(raw_event)
        if normalizer is None:
            protocol = raw_event.raw_data.get("protocol", "<unknown>")
            raise NormalizationError(
                f"No normalizer registered for protocol '{protocol}'"
            )

        return normalizer.normalize(raw_event)
