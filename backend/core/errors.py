"""
SanitialX error hierarchy.

All application-specific exceptions descend from :class:`SanitialXError`.
This module is pure-domain — it must never import infrastructure packages
(redis, fastapi, scapy, sqlalchemy, psycopg).
"""

from __future__ import annotations


class SanitialXError(Exception):
    """Root exception for the entire SanitialX application."""


# ── Configuration Errors ─────────────────────────────────────────────────

class ConfigurationError(SanitialXError):
    """Raised when application configuration is invalid or missing."""


# ── Validation Errors ────────────────────────────────────────────────────

class ValidationError(SanitialXError):
    """Raised when domain validation fails (distinct from Pydantic)."""


# ── Sensor Errors ────────────────────────────────────────────────────────

class SensorError(SanitialXError):
    """Base class for sensor-related errors."""


class SensorStartError(SensorError):
    """Raised when a sensor fails to start."""


class SensorStopError(SensorError):
    """Raised when a sensor fails to stop cleanly."""


# ── Normalizer Errors ────────────────────────────────────────────────────

class NormalizerError(SanitialXError):
    """Base class for normalizer-related errors."""


class NormalizationError(NormalizerError):
    """Raised when event normalization fails."""


# ── Pipeline Errors ──────────────────────────────────────────────────────

class PipelineError(SanitialXError):
    """Base class for pipeline-related errors."""


# ── Correlation Errors (Phase 8+) ────────────────────────────────────────

class CorrelationError(SanitialXError):
    """Base class for correlation-related errors."""


# ── Incident Errors (Phase 10+) ─────────────────────────────────────────

class IncidentError(SanitialXError):
    """Base class for incident-related errors."""


class IncidentConflictError(IncidentError):
    """Raised on optimistic-concurrency conflict during incident update."""
