"""
FastAPI Lifespan Manager for SentinelX.

Architecture Invariant (architecture.md §15):
- Explicit ordered startup and shutdown sequence.
- Container attached to app.state.container.

Startup order:
  1. Load Settings
  2. Init Database (session manager)
  3. Init Redis & EventBus (if live infrastructure available, else fallback)
  4. Create ApplicationContainer
  5. Verify Infrastructure
  6. Start Sensors (SensorManager.start_all())
  7. Start Correlation Worker (if available)
  8. Mark ready (app.state.is_ready = True)

Shutdown order:
  1. Mark not ready (app.state.is_ready = False)
  2. Stop Correlation Worker
  3. Stop Sensors (SensorManager.stop_all())
  4. Close EventBus / Redis
  5. Close Database (db_manager.close())
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI

from core.config import get_settings
from core.container import ApplicationContainer
from event_bus.redis_bus import RedisEventBus

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """FastAPI application lifespan context manager."""
    logger.info("Initializing SentinelX application lifecycle...")
    app.state.is_ready = False

    # 1. Load Settings
    settings = get_settings()

    # 2. Create ApplicationContainer (unless overridden by tests)
    container: ApplicationContainer = getattr(app.state, "container", None)
    if container is None:
        container = ApplicationContainer(settings=settings)

        # 3. Try to init Redis EventBus
        try:
            redis_bus = RedisEventBus.from_url(settings.REDIS_URL)
            container.attach_redis_bus(redis_bus)
            logger.info("Connected to Redis EventBus at %s", settings.REDIS_URL)
        except Exception as exc:
            logger.warning(
                "Could not connect to Redis at %s (%s). Proceeding without live Redis event bus.",
                settings.REDIS_URL,
                exc,
            )

        # Attach container to app state
        app.state.container = container

    # Auto-create DB tables if needed
    try:
        await container.db_manager.create_tables()
        logger.info("Verified/created database schema tables.")
    except Exception as exc:
        logger.warning("Database schema create_tables note: %s", exc)

    # 4. Start Sensors
    try:
        await container.sensor_manager.start_all()
        logger.info("Started all registered sensors.")
    except Exception as exc:
        logger.error("Failed to start sensors: %s", exc)

    # 5. Start Correlation Worker
    if container.correlation_worker is not None:
        try:
            await container.correlation_worker.start()
            logger.info("Started CorrelationWorker.")
        except Exception as exc:
            logger.error("Failed to start CorrelationWorker: %s", exc)

    # 6. Mark Ready
    app.state.is_ready = True
    logger.info("SentinelX application startup complete and READY.")

    yield

    # ── SHUTDOWN SEQUENCE ─────────────────────────────────────────────
    logger.info("Initiating SentinelX application shutdown sequence...")
    app.state.is_ready = False

    # 1. Stop Correlation Worker
    if container.correlation_worker is not None:
        try:
            await container.correlation_worker.stop()
            logger.info("CorrelationWorker stopped.")
        except Exception as exc:
            logger.error("Error stopping CorrelationWorker: %s", exc)

    # 2. Stop Sensors
    try:
        await container.sensor_manager.stop_all()
        logger.info("All sensors stopped.")
    except Exception as exc:
        logger.error("Error stopping sensors: %s", exc)

    # 3. Close Event Bus / Redis
    if container.event_bus is not None and isinstance(container.event_bus, RedisEventBus):
        try:
            await container.event_bus.close()
            logger.info("Redis EventBus closed.")
        except Exception as exc:
            logger.error("Error closing Redis EventBus: %s", exc)

    # 4. Close Database
    try:
        await container.db_manager.close()
        logger.info("Database connection pool closed.")
    except Exception as exc:
        logger.error("Error closing database: %s", exc)

    logger.info("SentinelX application shutdown complete.")
