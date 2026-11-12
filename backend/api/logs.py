"""Log monitoring API — AI-assisted log triage."""

from __future__ import annotations

import asyncio
import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from api.deps import get_current_user
from core.config import get_settings
from core.security import TokenPayload
from services.ai_log_analysis import analyze_logs, fallback_log_analysis

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/logs", tags=["Monitoring & Logs"])


class LogAnalyzeRequest(BaseModel):
    logs: str = Field(..., min_length=1, max_length=20_000)


@router.post("/analyze")
async def analyze_log_text(
    payload: LogAnalyzeRequest,
    _user: Annotated[TokenPayload, Depends(get_current_user)],
) -> dict[str, Any]:
    """Explain log text and surface the alert-worthy lines.

    Uses Gemini when a key is configured; otherwise a deterministic keyword
    triage still flags the obvious suspicious lines so the endpoint always
    returns something useful.
    """
    settings = get_settings()
    if settings.gemini_api_key:
        try:
            result = await asyncio.to_thread(
                analyze_logs,
                payload.logs,
                api_key=settings.gemini_api_key,
                model=settings.gemini_model,
            )
            return {"mode": "AI", **result.model_dump()}
        except Exception as exc:  # noqa: BLE001 - fall back to keyword triage
            logger.warning("Gemini log analysis failed, using fallback: %s", exc)

    return {"mode": "FALLBACK", **fallback_log_analysis(payload.logs).model_dump()}
