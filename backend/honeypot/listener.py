"""Low-interaction honeypot decoy listeners.

A decoy binds a port, sends a plausible banner, reads a bounded amount of
whatever the client sends, and records the interaction as a honeypot session.
It is deliberately low-interaction: attacker input is captured and sanitized
for logging only — it is NEVER executed, echoed back, or used to shape a
response. That keeps the decoy safe to run while still producing the local
"this service is being attacked right now" signal the exposure view consumes.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Awaitable, Callable

# Plausible-looking banners so a scanner records a "hit". Static bytes only;
# the decoy never adapts its response to attacker input.
BANNERS: dict[str, bytes] = {
    "SSH": b"SSH-2.0-OpenSSH_8.9p1\r\n",
    "TELNET": b"\r\nUbuntu 22.04 LTS\r\nlogin: ",
    "WEB": b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"admin\"\r\n\r\n",
    "DB": b"",
}

Sink = Callable[[dict], Awaitable[None]]

_READ_LIMIT = 4096
_READ_TIMEOUT = 5.0
_SNIPPET_MAX = 200


def _banner_for(service: str) -> bytes:
    label = service.upper()
    for key, banner in BANNERS.items():
        if key in label:
            return banner
    return b""


def _sanitize(raw: bytes) -> str:
    """Printable, bounded, single-line snippet of captured bytes — never run."""
    text = raw.decode("utf-8", errors="replace")
    cleaned = "".join(ch if 32 <= ord(ch) < 127 else " " for ch in text).strip()
    cleaned = " ".join(cleaned.split())
    return cleaned[:_SNIPPET_MAX]


def parse_port_services(spec: str) -> list[tuple[int, str]]:
    """Parse 'port:service,port:service' into [(port, service)] pairs."""
    pairs: list[tuple[int, str]] = []
    for item in spec.split(","):
        item = item.strip()
        if not item or ":" not in item:
            continue
        port_str, _, service = item.partition(":")
        service = service.strip()
        try:
            port = int(port_str.strip())
        except ValueError:
            continue
        if service and 1 <= port <= 65535:
            pairs.append((port, service))
    return pairs


class HoneypotListener:
    """A single decoy on one TCP port."""

    def __init__(
        self,
        *,
        port: int,
        service: str,
        sink: Sink,
        host: str = "0.0.0.0",
        read_limit: int = _READ_LIMIT,
        read_timeout: float = _READ_TIMEOUT,
    ) -> None:
        self._port = port
        self._service = service
        self._sink = sink
        self._host = host
        self._read_limit = read_limit
        self._read_timeout = read_timeout
        self._server: asyncio.AbstractServer | None = None

    @property
    def port(self) -> int:
        """Actual bound port (meaningful after start(), e.g. when asked for 0)."""
        if self._server is not None and self._server.sockets:
            return self._server.sockets[0].getsockname()[1]
        return self._port

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self._host, self._port)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        started_at = datetime.now(timezone.utc)
        peername = writer.get_extra_info("peername")
        attacker_ip = peername[0] if peername else "unknown"
        snippet = ""
        try:
            banner = _banner_for(self._service)
            if banner:
                writer.write(banner)
                await writer.drain()
            try:
                raw = await asyncio.wait_for(reader.read(self._read_limit), timeout=self._read_timeout)
                snippet = _sanitize(raw)
            except (asyncio.TimeoutError, ConnectionError):
                pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:  # noqa: BLE001 - closing a decoy socket must never raise out
                pass

        duration = int((datetime.now(timezone.utc) - started_at).total_seconds())
        session = {
            "session_id": str(uuid.uuid4()),
            "attacker_ip": attacker_ip,
            "service": self._service,
            "started_at": started_at,
            "duration_seconds": max(0, duration),
            "credentials_attempted": [],
            "commands_executed": [snippet] if snippet else [],
            "files_accessed": [],
            "risk_score": 70,
            "notes": f"Low-interaction {self._service} decoy capture.",
        }
        await self._sink(session)


class HoneypotManager:
    """Starts and stops a set of decoy listeners together."""

    def __init__(self, listeners: list[HoneypotListener]) -> None:
        self._listeners = listeners

    @classmethod
    def from_spec(cls, *, spec: str, sink: Sink, host: str = "0.0.0.0") -> "HoneypotManager":
        listeners = [
            HoneypotListener(port=port, service=service, sink=sink, host=host)
            for port, service in parse_port_services(spec)
        ]
        return cls(listeners)

    @property
    def listeners(self) -> list[HoneypotListener]:
        return list(self._listeners)

    async def start_all(self) -> None:
        for listener in self._listeners:
            await listener.start()

    async def stop_all(self) -> None:
        for listener in self._listeners:
            await listener.stop()
