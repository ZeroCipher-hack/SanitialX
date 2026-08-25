"""
Canonical event model for SentinelX.

NormalizedEvent is the single, immutable, domain-level event representation.
It is frozen (immutable), uses UTC-aware timestamps, and auto-generates
a unique event_id on construction.

This module is pure-domain — it must never import infrastructure packages
(redis, fastapi, scapy, sqlalchemy, psycopg).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class NormalizedEvent(BaseModel):
    """Canonical immutable event produced by normalizers.

    Invariants
    ----------
    - ``event_id`` is auto-generated (UUID4) if not supplied.
    - ``timestamp`` must be timezone-aware and in UTC.
    - The model is **frozen** — mutation raises an error.
    - No infrastructure imports are allowed in this module.
    """

    model_config = ConfigDict(frozen=True)

    event_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique event identifier (UUID4)",
    )
    event_type: str = Field(
        ...,
        description="Event type — should be an EventType value",
    )
    timestamp: datetime = Field(
        ...,
        description="When the event was observed (must be UTC-aware)",
    )
    source_ip: str | None = Field(
        default=None,
        description="Source IP address if applicable",
    )
    destination_ip: str | None = Field(
        default=None,
        description="Destination IP address if applicable",
    )
    source_port: int | None = Field(
        default=None,
        description="Source port if applicable",
    )
    destination_port: int | None = Field(
        default=None,
        description="Destination port if applicable",
    )
    protocol: str | None = Field(
        default=None,
        description="Network protocol (e.g. TCP, UDP, ARP)",
    )
    sensor_id: str = Field(
        ...,
        description="Identifier of the sensor that produced this event",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional event metadata (key-value pairs)",
    )

    @field_validator("timestamp")
    @classmethod
    def _validate_utc_aware(cls, v: datetime) -> datetime:
        """Reject naive timestamps and enforce UTC."""
        if v.tzinfo is None:
            raise ValueError(
                "Timestamp must be timezone-aware (UTC). "
                "Received a naive datetime."
            )
        # Normalise to UTC
        return v.astimezone(timezone.utc)
