"""Unit tests for core.errors — SentinelXError hierarchy."""

from __future__ import annotations

import pytest

from core.errors import (
    ConfigurationError,
    CorrelationError,
    IncidentConflictError,
    IncidentError,
    NormalizationError,
    NormalizerError,
    PipelineError,
    SensorError,
    SensorStartError,
    SensorStopError,
    SentinelXError,
    ValidationError,
)


class TestErrorHierarchy:
    """Validate the exception hierarchy relationships."""

    def test_root_is_exception(self) -> None:
        assert issubclass(SentinelXError, Exception)

    @pytest.mark.parametrize(
        "exc_cls",
        [
            ConfigurationError,
            ValidationError,
            SensorError,
            NormalizerError,
            PipelineError,
            CorrelationError,
            IncidentError,
        ],
    )
    def test_direct_children(self, exc_cls: type) -> None:
        """Each category error must be a direct or indirect child of SentinelXError."""
        assert issubclass(exc_cls, SentinelXError)

    def test_sensor_sub_errors(self) -> None:
        assert issubclass(SensorStartError, SensorError)
        assert issubclass(SensorStopError, SensorError)

    def test_normalizer_sub_errors(self) -> None:
        assert issubclass(NormalizationError, NormalizerError)

    def test_incident_sub_errors(self) -> None:
        assert issubclass(IncidentConflictError, IncidentError)

    def test_catch_all(self) -> None:
        """Catching SentinelXError must catch every sub-error."""
        for exc_cls in (
            ConfigurationError,
            ValidationError,
            SensorStartError,
            SensorStopError,
            NormalizationError,
            PipelineError,
            CorrelationError,
            IncidentConflictError,
        ):
            with pytest.raises(SentinelXError):
                raise exc_cls("test")

    def test_no_infrastructure_imports(self) -> None:
        """errors.py must not import any infrastructure package."""
        import importlib
        import inspect

        mod = importlib.import_module("core.errors")
        source = inspect.getsource(mod)
        for forbidden in ("redis", "fastapi", "scapy", "sqlalchemy", "psycopg"):
            assert f"import {forbidden}" not in source
