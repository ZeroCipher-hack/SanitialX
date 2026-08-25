"""
Incident domain model for SentinelX.

Invariants (architecture.md #5 & #7):
- Frozen (immutable) domain model to prevent accidental direct in-memory mutation.
- Includes optimistic concurrency version counter (version: int = 1).
- Pure domain — zero infrastructure imports.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from correlation.enums import Severity
from incidents.enums import IncidentStatus


class Incident(BaseModel):
    """Immutable domain representation of a security incident.

    Optimistic Concurrency Control:
    The ``version`` field is incremented on each state change. Repository
    updates must match expected version.
    """

    model_config = ConfigDict(frozen=True)

    incident_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this incident (UUID4)",
    )
    title: str = Field(
        ...,
        description="Summary title of the incident",
    )
    description: str = Field(
        ...,
        description="Detailed description of the incident",
    )
    severity: Severity = Field(
        ...,
        description="Incident severity level",
    )
    status: IncidentStatus = Field(
        default=IncidentStatus.OPEN,
        description="Current lifecycle status",
    )
    version: int = Field(
        default=1,
        description="Optimistic concurrency version number",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Creation timestamp (UTC-aware)",
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Last update timestamp (UTC-aware)",
    )
    source_ip: str | None = Field(
        default=None,
        description="Associated source IP",
    )
    destination_ip: str | None = Field(
        default=None,
        description="Associated destination IP",
    )
    triggering_detection_ids: list[str] = Field(
        default_factory=list,
        description="IDs of Detections that triggered this incident",
    )
    context: dict[str, Any] = Field(
        default_factory=dict,
        description="Forensic context and metadata",
    )

    @field_validator("created_at", "updated_at")
    @classmethod
    def _validate_utc_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("Incident timestamp must be timezone-aware (UTC).")
        return v.astimezone(timezone.utc)
