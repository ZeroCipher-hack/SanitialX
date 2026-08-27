"""
Auth Router for SentinelX — JWT Token Generation.

Endpoints:
- POST /api/v1/auth/token (Verifies credentials against stored, hashed
  passwords and issues a JWT bearer token carrying the user's actual role.)
- POST /api/v1/auth/logout (Revokes the caller's current token when Redis is
  available so it can no longer be replayed before expiry.)
"""

from __future__ import annotations

import logging
import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from api.deps import get_container, get_current_user, get_user_repository
from core.container import ApplicationContainer
from core.rate_limit import check_login_rate_limit, reset_login_rate_limit
from core.security import TokenPayload, create_access_token, hash_password, verify_password
from db.repositories.user_repository import PostgresUserRepository

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Authentication"])


class TokenRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str


_INVALID_CREDENTIALS_DETAIL = "Incorrect username or password."
_RATE_LIMITED_DETAIL = "Too many login attempts. Try again later."

_DUMMY_PASSWORD_HASH = hash_password(f"__no-such-user__{secrets.token_hex(16)}")


def _client_ip(request: Request) -> str:
    """Best-effort client IP for rate-limit keying."""
    return request.client.host if request.client else "unknown"


async def _safe_login_rate_limit(container: ApplicationContainer, rate_key: str) -> bool:
    """Use Redis rate limiting when available; fail open only on infrastructure failure.

    Redis is an optimization/control-plane dependency for authentication. A bad
    or temporarily unavailable Redis instance must not turn a valid credential
    into a generic HTTP 500 and lock the operator out of the console.
    """
    try:
        return await check_login_rate_limit(container.redis_client, rate_key)
    except Exception as exc:
        logger.error("Redis login rate limiter unavailable: %s", exc)
        return True


async def _safe_reset_login_rate_limit(container: ApplicationContainer, rate_key: str) -> None:
    """Reset the Redis login counter when Redis is available."""
    try:
        await reset_login_rate_limit(container.redis_client, rate_key)
    except Exception as exc:
        logger.error("Redis login rate limiter reset unavailable: %s", exc)


@router.post("/token", response_model=TokenResponse)
async def login_for_access_token(
    payload: TokenRequest,
    request: Request,
    container: Annotated[ApplicationContainer, Depends(get_container)],
    user_repository: Annotated[PostgresUserRepository, Depends(get_user_repository)],
) -> TokenResponse:
    """Issue a JWT bearer token after verifying the user's password.

    The role embedded in the token comes from the stored user record —
    it is never accepted from the client, so a caller cannot self-escalate
    to 'admin' by simply asking for it.

    Rate limited per (client IP, username) pair when Redis is healthy.
    """
    rate_key = f"{_client_ip(request)}:{payload.username}"
    if not await _safe_login_rate_limit(container, rate_key):
        logger.warning(
            "Rate limit exceeded for login attempts on username '%s' from %s.",
            payload.username,
            _client_ip(request),
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=_RATE_LIMITED_DETAIL,
        )

    user = await user_repository.get_by_username(payload.username)

    password_hash = user.password_hash if user is not None else _DUMMY_PASSWORD_HASH
    password_ok = verify_password(payload.password, password_hash)

    if user is None or not user.is_active or not password_ok:
        logger.warning("Failed login attempt for username '%s'.", payload.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_INVALID_CREDENTIALS_DETAIL,
            headers={"WWW-Authenticate": "Bearer"},
        )

    await _safe_reset_login_rate_limit(container, rate_key)

    token = create_access_token(
        subject=user.username,
        role=user.role,
        secret_key=container.settings.jwt_secret_key,
        algorithm=container.settings.jwt_algorithm,
    )

    return TokenResponse(access_token=token, role=user.role)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    current_user: Annotated[TokenPayload, Depends(get_current_user)],
    container: Annotated[ApplicationContainer, Depends(get_container)],
) -> None:
    """Revoke the bearer token used for this request when Redis is available."""
    remaining_ttl = max(int(current_user.exp - _now_epoch()), 1)
    try:
        await container.redis_client.setex(
            f"revoked_jti:{current_user.jti}", remaining_ttl, "1"
        )
    except Exception as exc:
        logger.error("Redis token revocation unavailable: %s", exc)


def _now_epoch() -> int:
    from datetime import datetime, timezone

    return int(datetime.now(timezone.utc).timestamp())
