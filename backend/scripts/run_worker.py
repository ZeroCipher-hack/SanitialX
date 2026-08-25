"""
Standalone entrypoint for the SentinelX correlation worker container.

Mirrors the relevant parts of core/lifecycle.py's startup sequence: a bare
ApplicationContainer has no event bus attached (event_bus stays None), so
container.correlation_worker stays None and calling .start() on it would
raise AttributeError. This script attaches a live RedisEventBus first,
exactly as the FastAPI backend process does at startup, then runs until
SIGTERM/SIGINT and shuts down cleanly.
"""

from __future__ import annotations

import asyncio
import logging
import signal

from core.config import get_settings
from core.container import ApplicationContainer
from event_bus.redis_bus import RedisEventBus

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sentinelx.worker")


async def main() -> None:
    settings = get_settings()
    container = ApplicationContainer(settings=settings)

    redis_bus = RedisEventBus.from_url(settings.REDIS_URL)
    container.attach_redis_bus(redis_bus)

    if container.correlation_worker is None:
        raise RuntimeError(
            "correlation_worker is still None after attach_redis_bus() — "
            "this indicates a bug in ApplicationContainer.attach_redis_bus()."
        )

    await container.correlation_worker.start()
    logger.info("CorrelationWorker running. Waiting for shutdown signal...")

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop_event.set)

    await stop_event.wait()
    logger.info("Shutdown signal received, stopping CorrelationWorker...")

    await container.correlation_worker.stop()
    await redis_bus.close()
    logger.info("CorrelationWorker shut down cleanly.")


if __name__ == "__main__":
    asyncio.run(main())
