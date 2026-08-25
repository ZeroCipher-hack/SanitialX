"""
SentinelX error hierarchy.

All application-specific exceptions descend from :class:`SentinelXError`.
This module is pure-domain — it must never import infrastructure packages
(redis, fastapi, scapy, sqlalchemy, psycopg).
"""

from __future__ import annotations


class SentinelXError(Exception):
    """Root exception for the entire SentinelX application."""


# ── Configuration Errors ─────────────────────────────────────────────────

class ConfigurationError(SentinelXError):
    """Raised when application configuration is invalid or missing."""


# ── Validation Errors ────────────────────────────────────────────────────

class ValidationError(SentinelXError):
    """Raised when domain validation fails (distinct from Pydantic)."""


# ── Sensor Errors ────────────────────────────────────────────────────────

class SensorError(SentinelXError):
    """Base class for sensor-related errors."""


class SensorStartError(SensorError):
    """Raised when a sensor fails to start."""


class SensorStopError(SensorError):
    """Raised when a sensor fails to stop cleanly."""


# ── Normalizer Errors ────────────────────────────────────────────────────

class NormalizerError(SentinelXError):
    """Base class for normalizer-related errors."""


class NormalizationError(NormalizerError):
    """Raised when event normalization fails."""


# ── Pipeline Errors ──────────────────────────────────────────────────────

class PipelineError(SentinelXError):
    """Base class for pipeline-related errors."""


# ── Correlation Errors (Phase 8+) ────────────────────────────────────────

class CorrelationError(SentinelXError):
    """Base class for correlation-related errors."""


# ── Incident Errors (Phase 10+) ─────────────────────────────────────────

class IncidentError(SentinelXError):
    """Base class for incident-related errors."""


class IncidentConflictError(IncidentError):
    """Raised on optimistic-concurrency conflict during incident update."""
