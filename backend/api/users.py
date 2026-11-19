"""User management for administrators (no public sign-up by design).

Security rules enforced here:
- admin only;
- an admin cannot demote, deactivate or lock out themselves, and the last active admin can never be removed;
- role change, deactivation and password reset immediately invalidate that user's existing sessions.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from api.deps import get_container, get_user_repository, require_role
from auth.models import User
from core.container import ApplicationContainer
from core.errors import ValidationError
from core.security import DEFAULT_EXPIRATION_MINUTES, TokenPayload, hash_password
from db.repositories.user_repository import PostgresUserRepository

router = APIRouter(prefix="/users", tags=["Users"])

Role = Literal["reader", "analyst", "admin"]
AdminOnly = Annotated[TokenPayload, Depends(require_role(["admin"]))]
Repo = Annotated[PostgresUserRepository, Depends(get_user_repository)]
Container = Annotated[ApplicationContainer, Depends(get_container)]


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    password: str = Field(min_length=8, max_length=128)
    role: Role


class UserUpdate(BaseModel):
    role: Role | None = None
    is_active: bool | None = None


class PasswordReset(BaseModel):
    password: str = Field(min_length=8, max_length=128)


def _public(user: User) -> dict:
    return {
        "user_id": user.user_id,
        "username": user.username,
        "role": user.role,
        "is_active": user.is_active,
        "created_at": user.created_at.isoformat(),
    }


async def _invalidate_sessions(container: ApplicationContainer, username: str) -> None:
    """Reject every token issued to this user before now."""
    await container.redis_client.setex(
        f"user_valid_after:{username}", DEFAULT_EXPIRATION_MINUTES * 60 + 60, int(time.time())
    )


async def _get_or_404(repo: PostgresUserRepository, user_id: str) -> User:
    user = await repo.get_by_id(user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found.")
    return user


@router.get("")
async def list_users(_admin: AdminOnly, repo: Repo):
    return [_public(u) for u in await repo.list_all()]


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_user(payload: UserCreate, _admin: AdminOnly, repo: Repo):
    user = User(
        user_id=str(uuid.uuid4()),
        username=payload.username,
        password_hash=hash_password(payload.password),
        role=payload.role,
        is_active=True,
        created_at=datetime.now(timezone.utc),
    )
    try:
        created = await repo.create(user)
    except ValidationError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    return _public(created)


@router.patch("/{user_id}")
async def update_user(user_id: str, payload: UserUpdate, admin: AdminOnly, repo: Repo, container: Container):
    user = await _get_or_404(repo, user_id)
    new_role = payload.role if payload.role is not None else user.role
    new_active = payload.is_active if payload.is_active is not None else user.is_active

    if user.username == admin.sub and (new_role != "admin" or not new_active):
        raise HTTPException(status.HTTP_409_CONFLICT, "You cannot demote or deactivate your own account.")
    removes_admin = user.role == "admin" and user.is_active and (new_role != "admin" or not new_active)
    if removes_admin and await repo.count_active_admins() <= 1:
        raise HTTPException(status.HTTP_409_CONFLICT, "At least one active administrator must remain.")

    updated = await repo.update(user_id, role=new_role, is_active=new_active)
    if new_role != user.role or new_active != user.is_active:
        await _invalidate_sessions(container, user.username)
    return _public(updated)


@router.post("/{user_id}/password")
async def reset_password(user_id: str, payload: PasswordReset, _admin: AdminOnly, repo: Repo, container: Container):
    user = await _get_or_404(repo, user_id)
    await repo.update(user_id, password_hash=hash_password(payload.password))
    await _invalidate_sessions(container, user.username)
    return {"status": "password_reset"}
