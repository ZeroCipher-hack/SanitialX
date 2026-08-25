"""
Detection domain model.

Represents a confirmed threat or suspicious pattern output by a DetectionRule.
Frozen (immutable), UTC-aware timestamp, auto-generated detection_id.
Pure domain module — no infrastructure imports.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from correlation.enums import Severity


class Detection(BaseModel):
    """Domain object produced when a DetectionRule triggers.

    Invariants:
    - Immutable (frozen).
    - Timestamp must be UTC-aware.
    - detection_id auto-generated UUID4 if not provided.
    - Pure domain model — zero infrastructure imports.
    """

    model_config = ConfigDict(frozen=True)

    detection_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for this detection (UUID4)",
    )
    rule_id: str = Field(
        ...,
        description="ID of the DetectionRule that fired",
    )
    rule_name: str = Field(
        ...,
        description="Human-readable name of the DetectionRule",
    )
    severity: Severity = Field(
        ...,
        description="Severity level of the detection",
    )
    title: str = Field(
        ...,
        description="Brief summary title of the detection",
    )
    description: str = Field(
        ...,
        description="Detailed explanation of why the rule fired",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the detection occurred (UTC-aware)",
    )
    source_ip: str | None = Field(
        default=None,
        description="Source IP involved in the threat",
    )
    destination_ip: str | None = Field(
        default=None,
        description="Destination IP involved in the threat",
    )
    triggering_event_ids: list[str] = Field(
        default_factory=list,
        description="IDs of NormalizedEvents that triggered this detection",
    )
    context: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional forensic context or rule metadata",
    )

    @field_validator("timestamp")
    @classmethod
    def _validate_utc_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("Detection timestamp must be timezone-aware (UTC).")
        return v.astimezone(timezone.utc)
