"""
ScapyNormalizer — normalizes RawEvents produced by ScapySensor.

Architecture invariants enforced:
  - TCP traffic → EventType.TCP  (NOT SSH_LOGIN, even on port 22)
  - ARP traffic → EventType.ARP_OBSERVED  (NOT ARP_SPOOF)
  - UDP traffic → EventType.UDP
  - ICMP traffic → EventType.ICMP
  - Never infers SSH_LOGIN or ARP_SPOOF — those require correlation evidence.
"""

from __future__ import annotations

from core.errors import NormalizationError
from events.enums import EventType
from events.models import NormalizedEvent
from normalizers.base import BaseNormalizer
from sensors.base import RawEvent

# Mapping from raw protocol strings to EventType values.
_PROTOCOL_MAP: dict[str, EventType] = {
    "TCP": EventType.TCP,
    "UDP": EventType.UDP,
    "ICMP": EventType.ICMP,
    "ARP": EventType.ARP_OBSERVED,
}


class ScapyNormalizer(BaseNormalizer):
    """Normalizes network-capture RawEvents into NormalizedEvents.

    Converts raw packet metadata (as extracted by ScapySensor) into
    the canonical :class:`NormalizedEvent` domain model.

    This normalizer only produces *observation* event types (TCP, UDP,
    ICMP, ARP_OBSERVED).  It never produces detection types (SSH_LOGIN,
    ARP_SPOOF, PORT_SCAN) — those require correlation evidence from
    dedicated detection rules.
    """

    def can_handle(self, raw_event: RawEvent) -> bool:
        """Return True if the raw event contains a ``protocol`` field
        we recognise."""
        protocol = raw_event.raw_data.get("protocol", "")
        return protocol in _PROTOCOL_MAP

    def normalize(self, raw_event: RawEvent) -> NormalizedEvent:
        """Convert a ScapySensor RawEvent to a NormalizedEvent.

        Raises
        ------
        NormalizationError
            If the raw event's protocol is not supported.
        """
        data = raw_event.raw_data
        protocol = data.get("protocol", "")

        event_type = _PROTOCOL_MAP.get(protocol)
        if event_type is None:
            raise NormalizationError(
                f"ScapyNormalizer cannot handle protocol '{protocol}'"
            )

        return NormalizedEvent(
            event_type=event_type.value,
            timestamp=raw_event.timestamp,
            source_ip=data.get("source_ip"),
            destination_ip=data.get("destination_ip"),
            source_port=data.get("source_port"),
            destination_port=data.get("destination_port"),
            protocol=protocol,
            sensor_id=raw_event.sensor_id,
            metadata={
                k: v
                for k, v in data.items()
                if k
                not in (
                    "protocol",
                    "source_ip",
                    "destination_ip",
                    "source_port",
                    "destination_port",
                )
            },
        )
