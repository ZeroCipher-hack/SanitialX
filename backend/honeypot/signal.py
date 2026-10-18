"""Honeypot deception signal → local active-threat correlation.

EPSS tells us the *global* probability a CVE is exploited. A honeypot hit
tells us something EPSS cannot: that an attacker is probing *this* network's
service *right now*. This module maps honeypot activity to service categories
and maps an asset's software to the same categories, so a live decoy hit can
raise the priority of the exposures it is actually relevant to.

The mapping is a deliberately transparent, conservative heuristic — documented
so it can be explained and later refined with real customer data.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

# Service category -> substrings that identify it, matched case-insensitively
# against both honeypot service labels and observed software vendor/product.
SERVICE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "SSH": ("ssh", "openssh", "dropbear"),
    "WEB": ("web", "http", "panel", "apache", "nginx", "httpd", "tomcat",
            "struts", "log4j", "spring", "iis"),
    "DB": ("db", "sql", "database", "postgres", "mysql", "mariadb", "mongo",
           "redis", "oracle", "mssql"),
    "RDP": ("rdp", "remote desktop", "terminal services"),
    "SMB": ("smb", "samba", "netbios", "eternalblue"),
}


def classify(text: str | None) -> set[str]:
    """Return the set of service categories a free-text label maps to."""
    if not text:
        return set()
    lowered = text.lower()
    return {
        category
        for category, needles in SERVICE_KEYWORDS.items()
        if any(needle in lowered for needle in needles)
    }


def software_categories(
    *, vendor: str = "", product: str = "", package_name: str | None = None
) -> set[str]:
    """Service categories an observed software identity belongs to."""
    return classify(" ".join(filter(None, (vendor, product, package_name or ""))))


def active_service_categories(
    sessions: Iterable[Any], *, within_hours: int = 24, now: datetime | None = None
) -> set[str]:
    """Service categories under active attack per recent honeypot sessions.

    ``sessions`` are honeypot session records (objects or dicts) carrying a
    ``service`` label and a ``started_at`` timestamp. Only sessions within the
    window count, so the signal reflects *current* activity, not history.
    """
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=max(1, within_hours))
    active: set[str] = set()
    for session in sessions:
        started_at = _get(session, "started_at")
        if started_at is not None and _as_aware(started_at) < cutoff:
            continue
        active |= classify(_get(session, "service"))
    return active


def _get(session: Any, key: str) -> Any:
    if isinstance(session, dict):
        return session.get(key)
    return getattr(session, key, None)


def _as_aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
