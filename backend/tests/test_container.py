"""Unit tests for ApplicationContainer dependency injection container."""

from __future__ import annotations

import pytest
from core.config import Settings
from core.container import ApplicationContainer

_TEST_SECRET_KWARGS = {
    "jwt_secret_key": "test-only-jwt-secret-" + "x" * 20,
    "api_key": "test-only-api-key-" + "x" * 20,
}


class TestApplicationContainer:
    def test_container_initialization(self) -> None:
        settings = Settings(
            ENVIRONMENT="testing",
            DATABASE_URL="sqlite+aiosqlite:///:memory:",
            **_TEST_SECRET_KWARGS,
        )
        container = ApplicationContainer(settings=settings)

        assert container.settings.ENVIRONMENT == "testing"
        assert container.normalizer_registry is not None
        assert container.dispatcher is not None
        assert container.pipeline is not None
        assert container.sensor_manager is not None
        assert container.correlation_engine is not None
        assert container.incident_service is not None

    def test_container_instances_are_isolated(self) -> None:
        """Confirming zero global mutable singletons."""
        s1 = Settings(ENVIRONMENT="testing", **_TEST_SECRET_KWARGS)
        s2 = Settings(ENVIRONMENT="testing", **_TEST_SECRET_KWARGS)

        c1 = ApplicationContainer(settings=s1)
        c2 = ApplicationContainer(settings=s2)

        assert c1 is not c2
        assert c1.sensor_manager is not c2.sensor_manager
        assert c1.pipeline is not c2.pipeline
