"""Unit tests for Phase 13 FastAPI application and lifecycle."""

from __future__ import annotations

import pytest
from async_asgi_testclient import TestClient

from main import app


class TestLifecycle:
    @pytest.mark.asyncio
    async def test_app_lifespan_startup_and_shutdown(self) -> None:
        async with TestClient(app) as client:
            assert app.state.is_ready is True
            assert app.state.container is not None
            assert app.state.container.sensor_manager is not None
