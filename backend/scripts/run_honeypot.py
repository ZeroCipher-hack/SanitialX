"""
Standalone entrypoint for SanitialX honeypot decoy listeners.

Binds the configured decoy ports and records every attacker interaction as a
honeypot session in the database. Those sessions become the local
"under active attack" signal that boosts matching exposures' risk.

Decoys are low-interaction: captured input is logged, never executed. The
process stays disabled unless SANITIALX_HONEYPOT_ENABLED is set true, so a
decoy never binds ports by accident.
"""

from __future__ import annotations

import asyncio
import logging
import signal

from core.config import get_settings
from db.repositories.honeypot_repository import PostgresHoneypotRepository
from db.session import DatabaseSessionManager
from honeypot.listener import HoneypotManager, parse_port_services

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sanitialx.honeypot")


async def main() -> None:
    settings = get_settings()
    if not settings.honeypot_enabled:
        logger.warning(
            "Honeypot decoys are disabled. Set SANITIALX_HONEYPOT_ENABLED=true to run them."
        )
        return

    pairs = parse_port_services(settings.honeypot_ports)
    if not pairs:
        logger.error("No valid decoys in SANITIALX_HONEYPOT_PORTS=%r.", settings.honeypot_ports)
        return

    db = DatabaseSessionManager(settings.DATABASE_URL)
    db.init()

    async def sink(session: dict) -> None:
        logger.info("Honeypot hit: %s on %s", session.get("attacker_ip"), session.get("service"))
        async with db.sessionmaker() as db_session:
            await PostgresHoneypotRepository(db_session).add_session(session)

    manager = HoneypotManager.from_spec(
        spec=settings.honeypot_ports, sink=sink, host=settings.honeypot_host
    )
    await manager.start_all()
    logger.info(
        "Honeypot decoys listening: %s",
        ", ".join(f"{port}:{service}" for port, service in pairs),
    )

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop_event.set)

    await stop_event.wait()
    logger.info("Shutdown signal received, stopping honeypot decoys...")
    await manager.stop_all()
    await db.close()
    logger.info("Honeypot decoys shut down cleanly.")


if __name__ == "__main__":
    asyncio.run(main())
