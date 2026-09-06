"""
FastAPI Lifespan Manager for SentinelX.

Architecture Invariant (architecture.md §15):
- Explicit ordered startup and shutdown sequence.
- Container attached to app.state.container.
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

    settings = get_settings()

    container: ApplicationContainer = getattr(app.state, "container", None)
    if container is None:
        container = ApplicationContainer(settings=settings)

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

        app.state.container = container

    # Verify/create tables before loading persisted runtime rules.
    try:
        await container.db_manager.create_tables()
        logger.info("Verified/created database schema tables.")
    except Exception as exc:
        logger.warning("Database schema create_tables note: %s", exc)

    # Load persisted, validated rule configurations into the live engine.
    # Invalid/legacy structured data is isolated so one stale row cannot block startup.
    try:
        result = await container.refresh_detection_rules()
        logger.info(
            "Applied persisted detection rules: %s applied, %s skipped.",
            result["applied"],
            result["skipped"],
        )
    except Exception as exc:
        logger.error("Failed to refresh persisted detection rules: %s", exc)

    try:
        await container.sensor_manager.start_all()
        logger.info("Started all registered sensors.")
    except Exception as exc:
        logger.error("Failed to start sensors: %s", exc)

    if container.correlation_worker is not None:
        try:
            await container.correlation_worker.start()
            logger.info("Started CorrelationWorker.")
        except Exception as exc:
            logger.error("Failed to start CorrelationWorker: %s", exc)

    app.state.is_ready = True
    logger.info("SentinelX application startup complete and READY.")

    yield

    logger.info("Initiating SentinelX application shutdown sequence...")
    app.state.is_ready = False

    if container.correlation_worker is not None:
        try:
            await container.correlation_worker.stop()
            logger.info("CorrelationWorker stopped.")
        except Exception as exc:
            logger.error("Error stopping CorrelationWorker: %s", exc)

    try:
        await container.sensor_manager.stop_all()
        logger.info("All sensors stopped.")
    except Exception as exc:
        logger.error("Error stopping sensors: %s", exc)

    if container.event_bus is not None and isinstance(container.event_bus, RedisEventBus):
        try:
            await container.event_bus.close()
            logger.info("Redis EventBus closed.")
        except Exception as exc:
            logger.error("Error closing Redis EventBus: %s", exc)

    try:
        await container.db_manager.close()
        logger.info("Database connection pool closed.")
    except Exception as exc:
        logger.error("Error closing database: %s", exc)

    logger.info("SentinelX application shutdown complete.")
