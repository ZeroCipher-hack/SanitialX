"""Persistence hook for live normalized security events."""

from __future__ import annotations

from db.repositories.event_repository import PostgresEventRepository
from events.models import NormalizedEvent


class LiveEventPersistenceHook:
    """Persist each consumed NormalizedEvent into ``security_events`` once."""

    def __init__(self, session_factory) -> None:
        self._session_factory = session_factory

    async def __call__(self, event: NormalizedEvent) -> bool:
        async with self._session_factory() as session:
            _model, created = await PostgresEventRepository(session).persist_normalized_event(event)
            return created
