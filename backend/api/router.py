"""
API v1 Router for SentinelX.

Mounts all sub-routers under /api/v1 per architecture specification (§3 resolution #4).
"""

from __future__ import annotations

from fastapi import APIRouter

from api.auth import router as auth_router
from api.health import router as health_router
from api.incidents import router as incidents_router
from api.rules import router as rules_router

api_v1_router = APIRouter(prefix="/api/v1")

api_v1_router.include_router(auth_router)
api_v1_router.include_router(health_router)
api_v1_router.include_router(incidents_router)
api_v1_router.include_router(rules_router)
