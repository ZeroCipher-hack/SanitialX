"""
Auth Router for SentinelX — JWT Token Generation.

Endpoints:
- POST /api/v1/auth/token  (Verifies credentials against stored, hashed
  passwords and issues a JWT bearer token carrying the user's actual role.)
- POST /api/v1/auth/logout (Revokes the caller's current token so it can no
  longer be used, even though it has not yet expired.)
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

# A syntactically valid PBKDF2 hash of a value no real password will equal.
# Used to force the same hashing work on unknown usernames as on known ones,
# so response timing does not reveal whether a username exists.
_DUMMY_PASSWORD_HASH = hash_password(f"__no-such-user__{secrets.token_hex(16)}")


def _client_ip(request: Request) -> str:
    """Best-effort client IP for rate-limit keying."""
    return request.client.host if request.client else "unknown"


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

    Rate limited per (client IP, username) pair: 5 attempts / 5 minutes.
    """
    rate_key = f"{_client_ip(request)}:{payload.username}"
    if not await check_login_rate_limit(container.redis_client, rate_key):
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

    # Always run a hash comparison, even on unknown usernames, using a fixed
    # dummy hash so that response timing does not reveal whether the
    # username exists (mitigates username enumeration via timing).
    password_hash = user.password_hash if user is not None else _DUMMY_PASSWORD_HASH
    password_ok = verify_password(payload.password, password_hash)

    if user is None or not user.is_active or not password_ok:
        logger.warning("Failed login attempt for username '%s'.", payload.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_INVALID_CREDENTIALS_DETAIL,
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Successful login — clear the rate-limit counter for this key so a
    # legitimate user isn't penalized by earlier typos.
    await reset_login_rate_limit(container.redis_client, rate_key)

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
    """Revoke the bearer token used for this request.

    Stores the token's jti in Redis until its natural expiry, so a token
    that has been logged out cannot be replayed even though the JWT
    signature itself is still valid.
    """
    remaining_ttl = max(int(current_user.exp - _now_epoch()), 1)
    await container.redis_client.setex(f"revoked_jti:{current_user.jti}", remaining_ttl, "1")


def _now_epoch() -> int:
    from datetime import datetime, timezone

    return int(datetime.now(timezone.utc).timestamp())
