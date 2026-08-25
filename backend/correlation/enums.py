"""
Severity and correlation enumerations.

Pure domain module — no infrastructure imports.
"""

from __future__ import annotations

from enum import Enum, unique


@unique
class Severity(str, Enum):
    """Severity level of a detection or incident."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
