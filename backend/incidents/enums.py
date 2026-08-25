"""
Incident status enumeration.

Pure domain module — no infrastructure imports.
"""

from __future__ import annotations

from enum import Enum, unique


@unique
class IncidentStatus(str, Enum):
    """Lifecycle status of a security incident.

    Allowed state transitions (enforced by IncidentService):
      OPEN -> INVESTIGATING | RESOLVED | CLOSED
      INVESTIGATING -> RESOLVED | CLOSED
      RESOLVED -> CLOSED | OPEN
      CLOSED -> OPEN
    """

    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"
