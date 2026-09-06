"""
Correlation state storage interface and in-memory implementation.

Per architecture.md §3 resolution #2:
v1 assumes a single CorrelationWorker process instance.

State store provides sliding window tracking, event deduplication per tracking key,
and memory bounds with automatic expiration/cleanup.
"""

from __future__ import annotations

import abc
import threading
from datetime import datetime, timezone

from events.models import NormalizedEvent


class CorrelationStateStore(abc.ABC):
    """Abstract interface for correlation state management."""

    @abc.abstractmethod
    def add_event(self, key: str, event: NormalizedEvent, ttl_seconds: float) -> bool:
        """Add an event under a tracking key (e.g. source_ip or rule_key).

        Returns True if the event was added, or False if the same event_id was
        already processed for this tracking key.
        """

    @abc.abstractmethod
    def get_events(self, key: str, window_seconds: float) -> list[NormalizedEvent]:
        """Return all non-expired events stored under key within the sliding window."""

    @abc.abstractmethod
    def clear_key(self, key: str) -> None:
        """Remove state for a specific key."""

    @abc.abstractmethod
    def cleanup_expired(self) -> int:
        """Evict expired events and keys across all stored state. Return count removed."""


class InMemoryCorrelationStateStore(CorrelationStateStore):
    """Thread-safe, bounded, in-memory state store for correlation rules.

    Maintains sliding window state for detection rules, with event_id deduplication
    scoped to each tracking key. Scoping is important because the same event may
    legitimately participate in multiple independent detection rules.
    """

    def __init__(self, default_ttl_seconds: float = 3600.0, max_keys: int = 10000) -> None:
        self._default_ttl = default_ttl_seconds
        self._max_keys = max_keys
        self._lock = threading.Lock()

        # Key -> list of (expire_at, event)
        self._store: dict[str, list[tuple[float, NormalizedEvent]]] = {}
        # (tracking key, event_id) -> expire_at timestamp for per-rule/key deduplication
        self._seen_events: dict[tuple[str, str], float] = {}

    def add_event(self, key: str, event: NormalizedEvent, ttl_seconds: float | None = None) -> bool:
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
        now = datetime.now(timezone.utc).timestamp()
        expire_at = now + ttl
        dedupe_key = (key, event.event_id)

        with self._lock:
            if dedupe_key in self._seen_events:
                if self._seen_events[dedupe_key] > now:
                    return False

            self._seen_events[dedupe_key] = expire_at

            if key not in self._store:
                if len(self._store) >= self._max_keys:
                    self._internal_cleanup_expired(now)
                self._store[key] = []

            self._store[key].append((expire_at, event))
            return True

    def get_events(self, key: str, window_seconds: float) -> list[NormalizedEvent]:
        now = datetime.now(timezone.utc).timestamp()
        cutoff = now - window_seconds

        with self._lock:
            if key not in self._store:
                return []

            valid_events = []
            retained = []
            for expire_at, event in self._store[key]:
                event_ts = event.timestamp.timestamp()
                if expire_at > now:
                    retained.append((expire_at, event))
                    if event_ts >= cutoff:
                        valid_events.append(event)

            self._store[key] = retained
            return valid_events

    def clear_key(self, key: str) -> None:
        with self._lock:
            self._store.pop(key, None)
            stale_seen = [item for item in self._seen_events if item[0] == key]
            for item in stale_seen:
                del self._seen_events[item]

    def cleanup_expired(self) -> int:
        now = datetime.now(timezone.utc).timestamp()
        with self._lock:
            return self._internal_cleanup_expired(now)

    def _internal_cleanup_expired(self, now: float) -> int:
        removed_count = 0

        expired_seen = [item for item, exp in self._seen_events.items() if exp <= now]
        for item in expired_seen:
            del self._seen_events[item]
            removed_count += 1

        empty_keys = []
        for key, event_list in list(self._store.items()):
            retained = [(exp, evt) for exp, evt in event_list if exp > now]
            removed_count += len(event_list) - len(retained)
            if not retained:
                empty_keys.append(key)
            else:
                self._store[key] = retained

        for key in empty_keys:
            del self._store[key]

        return removed_count
