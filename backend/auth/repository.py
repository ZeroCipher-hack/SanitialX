"""
UserRepository abstraction for SentinelX.

Defines the contract for persistent storage/lookup of Users.
Pure domain interface — no infrastructure imports allowed.
"""

from __future__ import annotations

import abc

from auth.models import User


class UserRepository(abc.ABC):
    """Abstract repository interface for Users."""

    @abc.abstractmethod
    async def get_by_username(self, username: str) -> User | None:
        """Fetch a User by username, or None if not found."""

    @abc.abstractmethod
    async def create(self, user: User) -> User:
        """Persist a new User."""
