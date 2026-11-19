"""
Postgres implementation of UserRepository interface.
"""

from __future__ import annotations

from datetime import timezone

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from auth.models import User
from auth.repository import UserRepository
from core.errors import ValidationError
from db.models.user import UserORM


def _orm_to_domain(orm: UserORM) -> User:
    created_at = orm.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    return User(
        user_id=orm.user_id,
        username=orm.username,
        password_hash=orm.password_hash,
        role=orm.role,
        is_active=orm.is_active,
        created_at=created_at,
    )


class PostgresUserRepository(UserRepository):
    """Postgres / SQLAlchemy implementation of UserRepository."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def get_by_username(self, username: str) -> User | None:
        async with self._session_factory() as session:
            result = await session.execute(
                select(UserORM).where(UserORM.username == username)
            )
            orm = result.scalar_one_or_none()
            if orm is None:
                return None
            return _orm_to_domain(orm)

    async def create(self, user: User) -> User:
        async with self._session_factory() as session:
            orm = UserORM(
                user_id=user.user_id,
                username=user.username,
                password_hash=user.password_hash,
                role=user.role,
                is_active=user.is_active,
                created_at=user.created_at,
            )
            session.add(orm)
            try:
                await session.commit()
            except IntegrityError as exc:
                await session.rollback()
                raise ValidationError(f"Username '{user.username}' is already taken.") from exc
            await session.refresh(orm)
            return _orm_to_domain(orm)

    async def list_all(self) -> list[User]:
        async with self._session_factory() as session:
            result = await session.execute(select(UserORM).order_by(UserORM.created_at, UserORM.username))
            return [_orm_to_domain(orm) for orm in result.scalars()]

    async def get_by_id(self, user_id: str) -> User | None:
        async with self._session_factory() as session:
            orm = await session.get(UserORM, user_id)
            return _orm_to_domain(orm) if orm is not None else None

    async def count_active_admins(self) -> int:
        async with self._session_factory() as session:
            result = await session.execute(
                select(func.count()).select_from(UserORM).where(UserORM.role == "admin", UserORM.is_active.is_(True))
            )
            return int(result.scalar_one())

    async def update(
        self,
        user_id: str,
        *,
        role: str | None = None,
        is_active: bool | None = None,
        password_hash: str | None = None,
    ) -> User | None:
        async with self._session_factory() as session:
            orm = await session.get(UserORM, user_id)
            if orm is None:
                return None
            if role is not None:
                orm.role = role
            if is_active is not None:
                orm.is_active = is_active
            if password_hash is not None:
                orm.password_hash = password_hash
            await session.commit()
            await session.refresh(orm)
            return _orm_to_domain(orm)
