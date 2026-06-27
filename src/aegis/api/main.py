"""FastAPI application factory and ASGI entry point.

Run with: ``uvicorn aegis.api.main:app``. In ``dev``/``test`` the app creates tables
on startup for convenience; in deployment, schema is managed by Alembic migrations.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from aegis.core.config import get_settings
from aegis.db.base import Base, get_engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    if settings.env in {"dev", "test"}:
        # Import models so they are registered on the metadata before create_all.
        import aegis.db.models  # noqa: F401

        Base.metadata.create_all(bind=get_engine())
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Aegis Sandbox API",
        version="0.1.0",
        description="AI-assisted multi-OS malware analysis — control plane (static phase).",
        lifespan=lifespan,
    )

    from aegis.api.routers import analyses, auth, samples

    app.include_router(auth.router)
    app.include_router(samples.router)
    app.include_router(analyses.router)

    @app.get("/health", tags=["meta"])
    def health():
        return {"status": "ok", "env": settings.env, "version": "0.1.0"}

    @app.get("/", tags=["meta"])
    def root():
        return {"service": "aegis-sandbox", "docs": "/docs"}

    return app


app = create_app()
