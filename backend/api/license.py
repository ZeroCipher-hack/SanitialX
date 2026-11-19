"""License status and installation endpoints."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from api.deps import get_container, get_current_user, require_role
from core.container import ApplicationContainer
from core.license import load_license, verify_license
from core.security import TokenPayload

router = APIRouter(prefix="/license", tags=["License"])


class LicenseDocument(BaseModel):
    payload: dict[str, Any]
    signature: str


@router.get("")
async def get_license_status(
    container: Annotated[ApplicationContainer, Depends(get_container)],
    _user: Annotated[TokenPayload, Depends(get_current_user)],
):
    s = container.settings
    return load_license(s.license_file, s.license_public_key).to_dict()


@router.post("")
async def install_license(
    document: LicenseDocument,
    container: Annotated[ApplicationContainer, Depends(get_container)],
    _user: Annotated[TokenPayload, Depends(require_role(["admin"]))],
):
    """Verify a license document and, only if it is valid, store it at the configured path."""
    s = container.settings
    if not s.license_file:
        raise HTTPException(status.HTTP_409_CONFLICT, "SENTINELX_LICENSE_FILE is not configured.")
    result = verify_license(document.model_dump(), s.license_public_key)
    if result.state not in ("VALID", "EXPIRED"):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, result.reason or "Invalid license.")
    Path(s.license_file).write_text(json.dumps(document.model_dump(), indent=2), encoding="utf-8")
    return result.to_dict()
