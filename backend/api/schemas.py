"""
API Request and Response schemas for SentinelX endpoints.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from correlation.enums import Severity
from correlation.rule_config import validate_rule_parameters
from incidents.enums import IncidentStatus


# ── Incident Schemas ──────────────────────────────────────────────────────

class IncidentResponse(BaseModel):
    incident_id: str
    title: str
    description: str
    severity: Severity
    status: IncidentStatus
    version: int
    created_at: datetime
    updated_at: datetime
    source_ip: str | None = None
    destination_ip: str | None = None
    triggering_detection_ids: list[str]
    context: dict[str, Any]


class IncidentStatusUpdate(BaseModel):
    status: IncidentStatus = Field(..., description="Target status for transition")
    expected_version: int | None = Field(
        default=None,
        description="Expected version for optimistic concurrency (optional in payload if supplied by headers/current state)",
    )


# ── Rule Schemas ──────────────────────────────────────────────────────────

class DetectionRuleResponse(BaseModel):
    rule_id: str
    rule_name: str
    description: str | None = None
    severity: Severity
    enabled: bool
    parameters: dict[str, Any]
    version: int
    created_at: datetime
    updated_at: datetime


class DetectionRuleUpdate(BaseModel):
    rule_name: str | None = Field(default=None, min_length=1, max_length=255)
    severity: Severity | None = None
    description: str | None = Field(default=None, max_length=512)
    enabled: bool | None = None
    parameters: dict[str, Any] | None = None
    expected_version: int | None = Field(default=None, ge=0)

    @field_validator("parameters")
    @classmethod
    def validate_parameters(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value is None:
            return None
        return validate_rule_parameters(value)


# ── Health Schemas ────────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str
    is_ready: bool
    details: dict[str, Any]
