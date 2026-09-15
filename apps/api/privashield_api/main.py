from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import __version__
from .config import Settings, get_settings
from .database import build_engine, build_session_factory, initialize_schema
from .repository import InMemoryEventRepository, SqlEventRepository
from .routes.events import router as events_router
from .routes.health import router as health_router


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved_settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.settings = resolved_settings
        app.state.database_engine = None

        if resolved_settings.database_enabled:
            engine = build_engine(resolved_settings.database_url)
            await initialize_schema(engine)
            session_factory = build_session_factory(engine)
            app.state.database_engine = engine
            app.state.event_repository = SqlEventRepository(session_factory)
        else:
            app.state.event_repository = InMemoryEventRepository()

        yield

        if app.state.database_engine is not None:
            await app.state.database_engine.dispose()

    app = FastAPI(
        title="PrivaShield API",
        version=__version__,
        description="Local-first PrivaShield control-plane API.",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=resolved_settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )

    app.include_router(health_router, prefix=resolved_settings.api_prefix)
    app.include_router(events_router, prefix=resolved_settings.api_prefix)

    @app.get("/", include_in_schema=False)
    async def root() -> dict[str, str]:
        return {
            "service": "PrivaShield API",
            "version": __version__,
            "docs": "/docs",
        }

    return app


app = create_app()
