"""Honeypot → local active-threat signal correlation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from honeypot.signal import (
    active_service_categories,
    classify,
    software_categories,
)


def test_classify_maps_labels_to_categories() -> None:
    assert classify("SSH brute force") == {"SSH"}
    assert classify("Fake Web Panel") == {"WEB"}
    assert classify("Fake DB / postgres") == {"DB"}
    assert classify("random noise") == set()
    assert classify(None) == set()


def test_software_categories_from_identity() -> None:
    assert software_categories(vendor="apache", product="log4j") == {"WEB"}
    assert software_categories(vendor="openssl", product="openssh") == {"SSH"}
    assert software_categories(vendor="postgresql", product="postgres") == {"DB"}
    assert software_categories(vendor="acme", product="widget") == set()


def test_active_categories_only_counts_recent_sessions() -> None:
    now = datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc)
    sessions = [
        {"service": "SSH", "started_at": now - timedelta(hours=1)},   # recent
        {"service": "Fake Web Panel", "started_at": now - timedelta(hours=48)},  # stale
        {"service": "Fake DB", "started_at": now - timedelta(hours=2)},  # recent
    ]
    active = active_service_categories(sessions, within_hours=24, now=now)
    assert active == {"SSH", "DB"}


def test_active_categories_handles_naive_timestamps() -> None:
    now = datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc)
    sessions = [{"service": "SSH", "started_at": datetime(2026, 10, 18, 11, 0)}]  # naive, recent
    assert active_service_categories(sessions, within_hours=24, now=now) == {"SSH"}
