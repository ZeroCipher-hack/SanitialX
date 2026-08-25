"""
FastAPI Dependencies for SentinelX.

Provides container injection, service access, and JWT Bearer authorization.
"""

from __future__ import annotations

from typing import Annotated, Sequence

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from core.container import ApplicationContainer
from core.security import TokenPayload, decode_access_token
from db.repositories.rule_repository import PostgresDetectionRuleRepository
from db.repositories.user_repository import PostgresUserRepository
from incidents.service import IncidentService

security_scheme = HTTPBearer(auto_error=False)


def get_container(request: Request) -> ApplicationContainer:
    """Retrieve ApplicationContainer from app state."""
    container: ApplicationContainer | None = getattr(request.app.state, "container", None)
    if container is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Application container not initialized.",
        )
    return container


def get_incident_service(
    container: Annotated[ApplicationContainer, Depends(get_container)],
) -> IncidentService:
    return container.incident_service


def get_rule_repository(
    container: Annotated[ApplicationContainer, Depends(get_container)],
) -> PostgresDetectionRuleRepository:
    return container.rule_repository


def get_user_repository(
    container: Annotated[ApplicationContainer, Depends(get_container)],
) -> PostgresUserRepository:
    return container.user_repository


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security_scheme)],
    container: Annotated[ApplicationContainer, Depends(get_container)],
) -> TokenPayload:
    """Decode and validate JWT Bearer token from HTTP Authorization header.

    Also rejects tokens whose jti has been revoked (e.g. via /auth/logout),
    even if the JWT signature and expiry are still valid.
    """
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Bearer authorization header.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_access_token(
            token=credentials.credentials,
            secret_key=container.settings.jwt_secret_key,
            algorithm=container.settings.jwt_algorithm,
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="JWT token has expired.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate JWT credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if await container.redis_client.exists(f"revoked_jti:{payload.jti}"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return payload


def require_role(allowed_roles: Sequence[str]):
    """Dependency factory enforcing role-based authorization."""
    async def role_checker(
        current_user: Annotated[TokenPayload, Depends(get_current_user)],
    ) -> TokenPayload:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"User role '{current_user.role}' lacks permission for this action. Allowed: {list(allowed_roles)}.",
            )
        return current_user

    return role_checker
