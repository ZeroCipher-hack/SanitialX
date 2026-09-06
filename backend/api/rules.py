"""
Detection Rules API router for SentinelX.

Endpoints:
- GET /rules (paginated, authenticated)
- GET /rules/{rule_id} (authenticated)
- PUT /rules/{rule_id} (requires analyst/admin role)
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from api.deps import (
    get_current_user,
    get_rule_repository,
    get_rule_runtime_manager,
    require_role,
)
from api.schemas import DetectionRuleResponse, DetectionRuleUpdate
from core.security import TokenPayload
from correlation.enums import Severity
from correlation.rule_runtime import DetectionRuleRuntimeManager
from db.repositories.rule_repository import (
    DetectionRuleVersionConflict,
    PostgresDetectionRuleRepository,
)

router = APIRouter(prefix="/rules", tags=["Detection Rules"])


@router.get("", response_model=list[DetectionRuleResponse])
async def list_rules(
    repo: Annotated[PostgresDetectionRuleRepository, Depends(get_rule_repository)],
    _user: Annotated[TokenPayload, Depends(get_current_user)],
    limit: int = Query(default=50, ge=1, le=1000, description="Page limit"),
    offset: int = Query(default=0, ge=0, description="Page offset"),
) -> list[DetectionRuleResponse]:
    """List detection rule configurations with pagination."""
    rules = await repo.list_rules(limit=limit, offset=offset)
    return [DetectionRuleResponse(**r) for r in rules]


@router.get("/{rule_id}", response_model=DetectionRuleResponse)
async def get_rule(
    rule_id: str,
    repo: Annotated[PostgresDetectionRuleRepository, Depends(get_rule_repository)],
    _user: Annotated[TokenPayload, Depends(get_current_user)],
) -> DetectionRuleResponse:
    """Fetch a detection rule configuration by ID."""
    rule = await repo.get_rule(rule_id)
    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule '{rule_id}' not found.",
        )
    return DetectionRuleResponse(**rule)


@router.put("/{rule_id}", response_model=DetectionRuleResponse)
async def update_rule(
    rule_id: str,
    payload: DetectionRuleUpdate,
    repo: Annotated[PostgresDetectionRuleRepository, Depends(get_rule_repository)],
    runtime: Annotated[DetectionRuleRuntimeManager, Depends(get_rule_runtime_manager)],
    _user: Annotated[TokenPayload, Depends(require_role(["admin", "analyst"]))],
) -> DetectionRuleResponse:
    """Persist and immediately apply a validated, versioned detection rule."""
    existing = await repo.get_rule(rule_id)
    if existing is None:
        rule_name = payload.rule_name or rule_id
        severity = payload.severity or Severity.HIGH
        description = payload.description
        enabled = payload.enabled if payload.enabled is not None else True
        parameters = payload.parameters or {}
    else:
        rule_name = payload.rule_name or existing["rule_name"]
        severity = payload.severity or Severity(existing["severity"])
        description = payload.description if payload.description is not None else existing["description"]
        enabled = payload.enabled if payload.enabled is not None else existing["enabled"]
        parameters = payload.parameters if payload.parameters is not None else existing["parameters"]

    try:
        await repo.save_rule(
            rule_id=rule_id,
            rule_name=rule_name,
            severity=severity.value,
            description=description,
            enabled=enabled,
            parameters=parameters,
            expected_version=payload.expected_version,
        )
    except DetectionRuleVersionConflict as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    updated = await repo.get_rule(rule_id)
    assert updated is not None

    # Apply after the database commit so the persisted version remains source of truth.
    # Legacy metadata-only rows are intentionally skipped; structured v1 rules hot-reload.
    runtime.apply_rule(updated)
    return DetectionRuleResponse(**updated)
