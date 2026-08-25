"""
Health endpoints for SentinelX.

Architecture Invariants:
- /health: liveness check only — MUST NOT perform Redis or Postgres calls. Completely unauthenticated for orchestrators/load balancers.
- /health/ready: readiness check — verifies application readiness and component health. Requires authentication.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import JSONResponse

from api.deps import get_container, get_current_user
from api.schemas import HealthResponse
from core.container import ApplicationContainer
from core.security import TokenPayload

router = APIRouter(prefix="/health", tags=["Health"])


@router.get("", response_model=HealthResponse)
async def liveness_check(request: Request) -> HealthResponse:
    """Liveness probe. Purely in-memory check — no DB or Redis calls. Unauthenticated."""
    return HealthResponse(
        status="ok",
        is_ready=getattr(request.app.state, "is_ready", False),
        details={"service": "SentinelX Backend"},
    )


@router.get("/ready", response_model=HealthResponse)
async def readiness_check(
    request: Request,
    container: Annotated[ApplicationContainer, Depends(get_container)],
    _user: Annotated[TokenPayload, Depends(get_current_user)],
) -> JSONResponse:
    """Readiness probe. Checks readiness flag and component health. Authenticated."""
    is_ready = getattr(request.app.state, "is_ready", False)

    details = {
        "sensors": container.sensor_manager.health_all(),
        "worker": (
            container.correlation_worker.get_health()
            if container.correlation_worker
            else None
        ),
    }

    if not is_ready:
        return JSONResponse(
            status_code=530,
            content={
                "status": "not_ready",
                "is_ready": False,
                "details": details,
            },
        )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "status": "ready",
            "is_ready": True,
            "details": details,
        },
    )
