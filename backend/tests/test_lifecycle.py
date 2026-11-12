"""Unit tests for Phase 13 FastAPI application and lifecycle."""

from __future__ import annotations

import pytest

from core.lifecycle import lifespan
from main import app


class TestLifecycle:
    @pytest.mark.asyncio
    async def test_app_lifespan_startup_and_shutdown(self) -> None:
        # Drive the lifespan context directly (httpx's ASGITransport does not
        # run lifespan events). External steps are resilient, so startup
        # completes even without reachable Redis/DB.
        async with lifespan(app):
            assert app.state.is_ready is True
            assert app.state.container is not None
            assert app.state.container.sensor_manager is not None
        assert app.state.is_ready is False
