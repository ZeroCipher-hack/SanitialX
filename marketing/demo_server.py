"""Run the real SanitialX API against throw-away SQLite + fakeredis for demos and screenshots.

  SENTINELX_FRONTEND_ORIGIN=http://localhost:3101 python marketing/demo_server.py

Prints a ready-to-use admin JWT. Nothing here touches PostgreSQL, Redis or the network.
"""
import asyncio, os, sys, tempfile
from pathlib import Path

os.environ.setdefault("SENTINELX_API_KEY", "demo-api-key-" + "x" * 24)
os.environ.setdefault("SENTINELX_JWT_SECRET_KEY", "demo-jwt-secret-" + "y" * 32)
os.environ.setdefault("SENTINELX_FRONTEND_ORIGIN", "http://localhost:3101")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

import fakeredis.aioredis
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.router import api_v1_router
from core.config import Settings
from core.container import ApplicationContainer
from core.security import create_access_token
from db.base import Base
from db.session import DatabaseSessionManager

db_file = Path(tempfile.gettempdir()) / f"sanitialx-demo-{os.environ.get('DEMO_PORT', '8010')}.db"
db_file.unlink(missing_ok=True)
settings = Settings(
    ENVIRONMENT="testing",
    DATABASE_URL=f"sqlite+aiosqlite:///{db_file}",
    redis_url="redis://localhost:6379/0",
)


async def lifespan(app: FastAPI):
    db = DatabaseSessionManager(settings.DATABASE_URL)
    db.init()
    async with db._engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    container = ApplicationContainer(settings=settings, db_manager=db)
    container.redis_client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    app.state.container = container
    app.state.is_ready = True
    yield
    await db.close()


app = FastAPI(lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=settings.frontend_origin.split(","), allow_methods=["*"], allow_headers=["*"])
app.include_router(api_v1_router)

if __name__ == "__main__":
    from datetime import timedelta
    token = create_access_token(subject="admin", role="admin", secret_key=settings.jwt_secret_key,
                                algorithm=settings.jwt_algorithm, expires_delta=timedelta(days=1))
    Path(tempfile.gettempdir(), "sanitialx-demo.token").write_text(token)
    uvicorn.run(app, host=os.environ.get("DEMO_HOST", "::1"), port=int(os.environ.get("DEMO_PORT", "8010")), log_level="warning")
