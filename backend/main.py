"""
SentinelX FastAPI Application Entrypoint.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.router import api_v1_router
from core.config import get_settings
from core.lifecycle import lifespan


def create_app() -> FastAPI:
    """FastAPI application factory."""
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        description="SentinelX Modular Production-Grade Async SIEM Backend",
        version="1.0.0",
        lifespan=lifespan,
    )
    origins = [o.strip() for o in settings.frontend_origin.split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(api_v1_router)
    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.debug,
    )
