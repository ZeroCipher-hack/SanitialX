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

from api.deps import get_current_user, get_rule_repository, require_role
from api.schemas import DetectionRuleResponse, DetectionRuleUpdate
from core.security import TokenPayload
from db.repositories.rule_repository import PostgresDetectionRuleRepository

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
    _user: Annotated[TokenPayload, Depends(require_role(["admin", "analyst"]))],
) -> DetectionRuleResponse:
    """Create or update a detection rule configuration. Requires admin or analyst role."""
    existing = await repo.get_rule(rule_id)
    if existing is None:
        rule_name = payload.rule_name or rule_id
        severity = payload.severity or "HIGH"
        description = payload.description
        enabled = payload.enabled if payload.enabled is not None else True
        parameters = payload.parameters or {}
    else:
        rule_name = payload.rule_name or existing["rule_name"]
        severity = payload.severity or existing["severity"]
        description = payload.description if payload.description is not None else existing["description"]
        enabled = payload.enabled if payload.enabled is not None else existing["enabled"]
        parameters = payload.parameters if payload.parameters is not None else existing["parameters"]

    await repo.save_rule(
        rule_id=rule_id,
        rule_name=rule_name,
        severity=severity,
        description=description,
        enabled=enabled,
        parameters=parameters,
    )

    updated = await repo.get_rule(rule_id)
    assert updated is not None
    return DetectionRuleResponse(**updated)
