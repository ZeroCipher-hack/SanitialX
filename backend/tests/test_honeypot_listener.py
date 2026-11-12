"""Low-interaction honeypot decoy listener."""

from __future__ import annotations

import asyncio

import pytest

from honeypot.listener import HoneypotListener, HoneypotManager, parse_port_services


def test_parse_port_services() -> None:
    assert parse_port_services("2222:SSH,8080:Fake Web Panel") == [
        (2222, "SSH"),
        (8080, "Fake Web Panel"),
    ]
    # Malformed entries are skipped, not fatal.
    assert parse_port_services("bad, 70000:X, 22:SSH, :NoPort, 80:") == [(22, "SSH")]
    assert parse_port_services("") == []


@pytest.mark.asyncio
async def test_listener_records_connection_and_sends_banner() -> None:
    captured: list[dict] = []

    async def sink(session: dict) -> None:
        captured.append(session)

    listener = HoneypotListener(port=0, service="SSH", sink=sink, host="127.0.0.1")
    await listener.start()
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", listener.port)
        banner = await asyncio.wait_for(reader.read(64), timeout=2.0)
        assert banner.startswith(b"SSH-2.0")  # plausible decoy banner
        writer.write(b"root:hunter2\r\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()
    finally:
        # Give the handler a moment to finish, then stop.
        for _ in range(50):
            if captured:
                break
            await asyncio.sleep(0.02)
        await listener.stop()

    assert len(captured) == 1
    session = captured[0]
    assert session["attacker_ip"] == "127.0.0.1"
    assert session["service"] == "SSH"
    # The attacker input is captured for logging, sanitized — never executed.
    assert session["commands_executed"] == ["root:hunter2"]
    assert session["risk_score"] == 70


async def _noop_sink(_session: dict) -> None:
    pass


def test_manager_from_spec_builds_one_listener_per_decoy() -> None:
    manager = HoneypotManager.from_spec(
        spec="2222:SSH,8080:Fake Web Panel", sink=_noop_sink, host="127.0.0.1"
    )
    services = sorted(l._service for l in manager.listeners)  # noqa: SLF001 - test introspection
    assert services == ["Fake Web Panel", "SSH"]


@pytest.mark.asyncio
async def test_manager_starts_and_stops_listeners() -> None:
    manager = HoneypotManager(
        [HoneypotListener(port=0, service="SSH", sink=_noop_sink, host="127.0.0.1")]
    )
    await manager.start_all()
    try:
        assert manager.listeners[0].port > 0  # bound to a real ephemeral port
    finally:
        await manager.stop_all()
