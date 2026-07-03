"""FastAPI application factory and ASGI entry point.

Run with: ``uvicorn aegis.api.main:app``. In ``dev``/``test`` the app creates tables
on startup for convenience; in deployment, schema is managed by Alembic migrations.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from aegis.core.config import get_settings
from aegis.db.base import Base, get_engine

_STATIC_DIR = Path(__file__).parent / "static"


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
        title="MalwareTotal API",
        version="0.1.0",
        description="AI-assisted multi-OS malware analysis — control plane (static phase).",
        lifespan=lifespan,
    )

    from aegis.api.routers import analyses, auth, corpus, samples

    app.include_router(auth.router)
    app.include_router(samples.router)
    app.include_router(analyses.router)
    app.include_router(corpus.router)

    @app.get("/health", tags=["meta"])
    def health():
        return {"status": "ok", "env": settings.env, "version": "0.1.0"}

    @app.get("/", include_in_schema=False)
    def root():
        # Send users to the console UI; API docs remain at /docs.
        return RedirectResponse(url="/ui/")

    # Web console (vanilla single-page app talking to /v1). html=True serves index.html
    # at the mount root.
    if _STATIC_DIR.is_dir():
        app.mount("/ui", StaticFiles(directory=str(_STATIC_DIR), html=True), name="ui")

    return app


app = create_app()
