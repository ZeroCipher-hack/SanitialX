"""
Event type enumeration for SentinelX.

This module defines the canonical set of event types that the system can
observe or detect. It is pure-domain — no infrastructure imports.

Note: ARP_OBSERVED ≠ ARP_SPOOF (architecture.md invariant #1).
      TCP on port 22 ≠ SSH_LOGIN (architecture.md invariant #2).
      Normalizers must never infer SSH_LOGIN or ARP_SPOOF; those require
      dedicated detection/correlation evidence.
"""

from __future__ import annotations

from enum import Enum, unique


@unique
class EventType(str, Enum):
    """Canonical event types recognised by SentinelX.

    Raw observation types — produced by sensors/normalizers:
      TCP          – a TCP packet observation
      UDP          – a UDP packet observation
      ICMP         – an ICMP packet observation
      ARP_OBSERVED – an observed ARP request or reply (NOT spoofing)
      DNS_QUERY    – a DNS query observation

    Detection types — produced only by correlation/detection rules:
      SSH_LOGIN    – confirmed SSH authentication event (requires log evidence)
      ARP_SPOOF    – confirmed ARP spoofing (requires correlation evidence)
      PORT_SCAN    – confirmed port-scan pattern (requires correlation evidence)

    Generic:
      UNKNOWN      – unrecognised event type
    """

    # Raw observations (sensors/normalizers may produce these)
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    ARP_OBSERVED = "ARP_OBSERVED"
    DNS_QUERY = "DNS_QUERY"

    # Detection events (only correlation/detection rules may produce these)
    SSH_LOGIN = "SSH_LOGIN"
    ARP_SPOOF = "ARP_SPOOF"
    PORT_SCAN = "PORT_SCAN"

    # Fallback
    UNKNOWN = "UNKNOWN"
