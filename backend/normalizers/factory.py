"""
Normalizer factory for SentinelX.

Provides a convenience function to build a pre-configured
:class:`NormalizerRegistry` with all known normalizers.
"""

from __future__ import annotations

from normalizers.registry import NormalizerRegistry
from normalizers.scapy import ScapyNormalizer


def create_default_registry() -> NormalizerRegistry:
    """Create a :class:`NormalizerRegistry` pre-loaded with the default
    normalizers.

    Currently registers:
    - :class:`ScapyNormalizer` for network packet events.
    """
    registry = NormalizerRegistry()
    registry.register(ScapyNormalizer())
    return registry
