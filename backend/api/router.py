"""
API v1 Router for SanitialX.

Mounts all sub-routers under /api/v1 per master architecture specification.
"""

from __future__ import annotations

from fastapi import APIRouter

from api.auth import router as auth_router
from api.health import router as health_router
from api.incidents import router as incidents_router
from api.rules import router as rules_router
from api.events import router as events_router
from api.agents import router as agents_router
from api.honeypots import router as honeypots_router
from api.simulations import router as simulations_router
from api.reports import router as reports_router
from api.attack_graph import router as attack_graph_router

api_v1_router = APIRouter(prefix="/api/v1")

api_v1_router.include_router(auth_router)
api_v1_router.include_router(health_router)
api_v1_router.include_router(incidents_router)
api_v1_router.include_router(rules_router)
api_v1_router.include_router(events_router)
api_v1_router.include_router(agents_router)
api_v1_router.include_router(honeypots_router)
api_v1_router.include_router(simulations_router)
api_v1_router.include_router(reports_router)
api_v1_router.include_router(attack_graph_router)
