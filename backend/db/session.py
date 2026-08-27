"""
Async SQLAlchemy 2.x session manager and engine factory.
"""

from __future__ import annotations

import logging
from typing import AsyncGenerator
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

logger = logging.getLogger(__name__)


def _normalize_database_url(database_url: str) -> str:
    """Normalize hosted PostgreSQL URLs for SQLAlchemy + asyncpg.

    asyncpg does not accept SQLAlchemy/psycopg-style ``sslmode`` as a
    connection keyword. Render/PostgreSQL URLs commonly contain
    ``sslmode=require``; asyncpg expects the equivalent ``ssl=require``.
    """
    parts = urlsplit(database_url)
    if parts.scheme not in {"postgres", "postgresql", "postgresql+asyncpg"}:
        return database_url

    query = parse_qsl(parts.query, keep_blank_values=True)
    normalized_query: list[tuple[str, str]] = []
    sslmode: str | None = None

    for key, value in query:
        if key.lower() == "sslmode":
            sslmode = value
            continue
        if key.lower() == "ssl":
            # Preserve an explicit asyncpg-compatible ssl setting.
            sslmode = None
        normalized_query.append((key, value))

    if sslmode and not any(key.lower() == "ssl" for key, _ in normalized_query):
        normalized_query.append(("ssl", sslmode))

    scheme = "postgresql+asyncpg" if parts.scheme in {"postgres", "postgresql"} else parts.scheme
    return urlunsplit((scheme, parts.netloc, parts.path, urlencode(normalized_query), parts.fragment))


class DatabaseSessionManager:
    """Manages async SQLAlchemy engine lifecycle and session creation."""

    def __init__(self, database_url: str, echo: bool = False) -> None:
        self._database_url = _normalize_database_url(database_url)
        self._echo = echo
        self._engine: AsyncEngine | None = None
        self._sessionmaker: async_sessionmaker[AsyncSession] | None = None

    def init(self) -> None:
        if self._engine is not None:
            return
        self._engine = create_async_engine(
            self._database_url,
            echo=self._echo,
            future=True,
        )
        self._sessionmaker = async_sessionmaker(
            bind=self._engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )

    async def create_tables(self) -> None:
        if self._engine is not None:
            from db.base import Base
            import db.models  # noqa: F401
            async with self._engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

    async def close(self) -> None:
        if self._engine is not None:
            await self._engine.dispose()
            self._engine = None
            self._sessionmaker = None

    @property
    def sessionmaker(self) -> async_sessionmaker[AsyncSession]:
        if self._sessionmaker is None:
            raise RuntimeError("DatabaseSessionManager is not initialized. Call init() first.")
        return self._sessionmaker

    async def session(self) -> AsyncGenerator[AsyncSession, None]:
        if self._sessionmaker is None:
            raise RuntimeError("DatabaseSessionManager is not initialized. Call init() first.")
        async with self._sessionmaker() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
