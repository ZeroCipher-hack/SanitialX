"""
FastAPI Lifespan Manager for SentinelX.

Architecture Invariant (architecture.md §15): explicit ordered startup/shutdown.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI

from core.config import get_settings
from core.container import ApplicationContainer
from db.repositories.agent_repository import PostgresAgentRepository
from event_bus.redis_bus import RedisEventBus

logger = logging.getLogger(__name__)


async def _agent_offline_monitor(container: ApplicationContainer, *, timeout_seconds: int, check_interval_seconds: int) -> None:
    """Continuously mark enrolled agents offline after their heartbeat deadline."""
    while True:
        try:
            async with container.db_manager.sessionmaker() as session:
                changed = await PostgresAgentRepository(session).mark_stale_agents_offline(
                    timeout_seconds=timeout_seconds
                )
            if changed:
                logger.warning("Marked %s stale SanitialX agent(s) OFFLINE.", changed)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("Agent offline monitor failed: %s", exc)
        await asyncio.sleep(check_interval_seconds)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info("Initializing SentinelX application lifecycle...")
    app.state.is_ready = False
    settings = get_settings()

    container: ApplicationContainer = getattr(app.state, "container", None)
    if container is None:
        container = ApplicationContainer(settings=settings)
        try:
            redis_bus = RedisEventBus.from_url(settings.REDIS_URL)
            container.attach_redis_bus(redis_bus)
            logger.info("Connected Redis EventBus and distributed correlation state at %s", settings.REDIS_URL)
        except Exception as exc:
            logger.warning("Could not initialize Redis at %s (%s). Proceeding with in-memory correlation state.", settings.REDIS_URL, exc)
        app.state.container = container

    try:
        await container.db_manager.create_tables()
        logger.info("Verified/created database schema tables.")
    except Exception as exc:
        logger.warning("Database schema create_tables note: %s", exc)

    try:
        result = await container.refresh_detection_rules()
        logger.info("Applied persisted detection rules: %s applied, %s skipped.", result["applied"], result["skipped"])
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

    offline_monitor_task = asyncio.create_task(
        _agent_offline_monitor(
            container,
            timeout_seconds=settings.agent_offline_timeout_seconds,
            check_interval_seconds=settings.agent_offline_check_interval_seconds,
        ),
        name="SanitialXAgentOfflineMonitor",
    )
    app.state.agent_offline_monitor = offline_monitor_task
    logger.info(
        "Started agent offline monitor (timeout=%ss check=%ss).",
        settings.agent_offline_timeout_seconds,
        settings.agent_offline_check_interval_seconds,
    )

    app.state.is_ready = True
    logger.info("SentinelX application startup complete and READY.")
    yield

    logger.info("Initiating SentinelX application shutdown sequence...")
    app.state.is_ready = False

    offline_monitor_task.cancel()
    try:
        await offline_monitor_task
    except asyncio.CancelledError:
        pass
    logger.info("Agent offline monitor stopped.")

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

    if container.correlation_redis_client is not None:
        try:
            container.correlation_redis_client.close()
            logger.info("Correlation Redis client closed.")
        except Exception as exc:
            logger.error("Error closing correlation Redis client: %s", exc)

    try:
        await container.db_manager.close()
        logger.info("Database connection pool closed.")
    except Exception as exc:
        logger.error("Error closing database: %s", exc)

    logger.info("SentinelX application shutdown complete.")
