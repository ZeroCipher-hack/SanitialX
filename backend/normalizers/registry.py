"""
Normalizer registry for SentinelX.

Maintains an ordered list of :class:`BaseNormalizer` instances and provides
lookup by :class:`RawEvent`.  Not a module-level singleton — must be
instantiated explicitly.
"""

from __future__ import annotations

from normalizers.base import BaseNormalizer
from sensors.base import RawEvent


class NormalizerRegistry:
    """Registry of normalizer instances, queried in registration order.

    Usage::

        registry = NormalizerRegistry()
        registry.register(scapy_normalizer)
        normalizer = registry.get_normalizer(raw_event)
    """

    def __init__(self) -> None:
        self._normalizers: list[BaseNormalizer] = []

    def register(self, normalizer: BaseNormalizer) -> None:
        """Register a normalizer. Later registrations have lower priority."""
        self._normalizers.append(normalizer)

    def get_normalizer(self, raw_event: RawEvent) -> BaseNormalizer | None:
        """Return the first registered normalizer that can handle *raw_event*,
        or ``None`` if none can."""
        for normalizer in self._normalizers:
            if normalizer.can_handle(raw_event):
                return normalizer
        return None

    @property
    def normalizers(self) -> list[BaseNormalizer]:
        """Read-only copy of registered normalizers."""
        return list(self._normalizers)
