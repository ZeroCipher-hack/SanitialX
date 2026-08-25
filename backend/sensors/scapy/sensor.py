"""
ScapySensor — network packet capture sensor using Scapy's AsyncSniffer.

Architecture invariants enforced:
  - Thread→asyncio bridge via asyncio.run_coroutine_threadsafe (#3)
  - Event loop captured in start() (#3)
  - Health counters protected with threading.Lock (#3, #8)
  - No payload retention beyond metadata extraction
  - Never fabricates SSH_LOGIN or ARP_SPOOF (#2, #1)
  - Only produces raw observations (TCP, UDP, ICMP, ARP_OBSERVED, etc.)
"""

from __future__ import annotations

import asyncio
import logging
import threading
from datetime import datetime, timezone
from typing import Any

from scapy.all import AsyncSniffer, Packet  # type: ignore[import-untyped]
from scapy.layers.inet import IP, TCP, UDP, ICMP  # type: ignore[import-untyped]
from scapy.layers.l2 import ARP  # type: ignore[import-untyped]

from sensors.base import BaseSensor, RawEvent, RawEventCallback

logger = logging.getLogger(__name__)


class ScapySensor(BaseSensor):
    """Captures network packets via Scapy and emits :class:`RawEvent` objects.

    The Scapy AsyncSniffer runs its callback on a background thread. This
    sensor bridges that thread into the asyncio event loop using
    ``asyncio.run_coroutine_threadsafe``, with the loop captured at
    ``start()`` time.

    Health counters (packets_captured, errors, last_error) are protected
    by a ``threading.Lock`` because they are mutated from the capture thread.
    """

    def __init__(
        self,
        sensor_id: str,
        callback: RawEventCallback,
        interface: str = "eth0",
        bpf_filter: str = "",
    ) -> None:
        super().__init__(sensor_id=sensor_id, callback=callback)
        self._interface = interface
        self._bpf_filter = bpf_filter

        # Runtime state
        self._sniffer: AsyncSniffer | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._running = False

        # Thread-safe health counters
        self._lock = threading.Lock()
        self._packets_captured = 0
        self._errors = 0
        self._last_error: str | None = None

    async def start(self) -> None:
        """Start the AsyncSniffer and capture the current event loop."""
        if self._running:
            return

        # Capture the running event loop — required for thread→asyncio bridge
        self._loop = asyncio.get_running_loop()

        sniffer_kwargs: dict[str, Any] = {
            "prn": self._on_packet,
            "store": False,
            "iface": self._interface,
        }
        if self._bpf_filter:
            sniffer_kwargs["filter"] = self._bpf_filter

        self._sniffer = AsyncSniffer(**sniffer_kwargs)
        self._sniffer.start()
        self._running = True
        logger.info(
            "ScapySensor '%s' started on interface '%s'",
            self._sensor_id,
            self._interface,
        )

    async def stop(self) -> None:
        """Stop the AsyncSniffer gracefully."""
        if not self._running or self._sniffer is None:
            return

        self._sniffer.stop()
        self._running = False
        self._sniffer = None
        logger.info("ScapySensor '%s' stopped", self._sensor_id)

    def is_running(self) -> bool:
        return self._running

    def health(self) -> dict[str, Any]:
        with self._lock:
            return {
                "running": self._running,
                "sensor_id": self._sensor_id,
                "interface": self._interface,
                "packets_captured": self._packets_captured,
                "errors": self._errors,
                "last_error": self._last_error,
            }

    # ── Private: packet handling (called from Scapy's capture thread) ────

    def _on_packet(self, packet: Packet) -> None:
        """Scapy callback — runs on the capture thread, NOT the event loop.

        Extracts minimal metadata, builds a RawEvent, and schedules the
        async callback on the captured event loop via
        ``asyncio.run_coroutine_threadsafe``.
        """
        try:
            raw_data = self._extract_metadata(packet)
            raw_event = RawEvent(
                sensor_id=self._sensor_id,
                timestamp=datetime.now(timezone.utc),
                raw_data=raw_data,
            )

            if self._loop is not None and not self._loop.is_closed():
                future = asyncio.run_coroutine_threadsafe(
                    self._callback(raw_event), self._loop
                )
                # We don't block on the future — fire-and-forget from
                # the capture thread. Errors are logged in _safe_callback
                # or via the future's exception callback.
                future.add_done_callback(self._future_error_handler)

            with self._lock:
                self._packets_captured += 1

        except Exception as exc:  # noqa: BLE001
            with self._lock:
                self._errors += 1
                self._last_error = str(exc)
            logger.error(
                "ScapySensor '%s' packet handling error: %s",
                self._sensor_id,
                exc,
            )

    @staticmethod
    def _future_error_handler(future: asyncio.Future) -> None:  # type: ignore[type-arg]
        """Log any exception from the scheduled coroutine."""
        if future.cancelled():
            return
        exc = future.exception()
        if exc is not None:
            logger.error("ScapySensor async callback error: %s", exc)

    @staticmethod
    def _extract_metadata(packet: Packet) -> dict[str, Any]:
        """Extract minimal network metadata from a Scapy packet.

        Returns only what the packet actually contains — never fabricates
        application-layer information (architecture invariants #1, #2).
        """
        meta: dict[str, Any] = {"packet_summary": packet.summary()}

        if packet.haslayer(IP):
            ip_layer = packet[IP]
            meta["source_ip"] = ip_layer.src
            meta["destination_ip"] = ip_layer.dst
            meta["ttl"] = ip_layer.ttl

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            meta["protocol"] = "TCP"
            meta["source_port"] = tcp_layer.sport
            meta["destination_port"] = tcp_layer.dport
            meta["tcp_flags"] = str(tcp_layer.flags)
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            meta["protocol"] = "UDP"
            meta["source_port"] = udp_layer.sport
            meta["destination_port"] = udp_layer.dport
        elif packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            meta["protocol"] = "ICMP"
            meta["icmp_type"] = icmp_layer.type
            meta["icmp_code"] = icmp_layer.code
        elif packet.haslayer(ARP):
            arp_layer = packet[ARP]
            meta["protocol"] = "ARP"
            meta["arp_op"] = arp_layer.op  # 1=request, 2=reply
            meta["source_ip"] = arp_layer.psrc
            meta["destination_ip"] = arp_layer.pdst
            meta["source_mac"] = arp_layer.hwsrc
            meta["destination_mac"] = arp_layer.hwdst

        return meta
