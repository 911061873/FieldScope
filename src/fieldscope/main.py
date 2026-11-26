from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from fieldscope.api.routers import (
    auth,
    external_apps,
    external_roles,
    health,
    platform_roles,
    platforms,
    users,
)
from fieldscope.core.config import Settings, get_settings
from fieldscope.core.crypto import SecretCipher
from fieldscope.db.seed import seed_initial_data
from fieldscope.db.session import DatabaseManager


def create_app(settings: Settings | None = None) -> FastAPI:
    cfg = settings or get_settings()
    db_manager = DatabaseManager(cfg.database_url, echo=cfg.debug)
    cipher = SecretCipher(cfg.encryption_key)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        await db_manager.create_tables()
        async with db_manager.session_factory() as session:
            await seed_initial_data(session, cfg)
        try:
            yield
        finally:
            await db_manager.dispose()

    app = FastAPI(
        title=cfg.app_name,
        version="0.1.0",
        description="面向企业的细粒度数据连接器平台（双轨 RBAC + API/MCP 双协议网关）",
        lifespan=lifespan,
    )
    app.state.settings = cfg
    app.state.db = db_manager
    app.state.cipher = cipher

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Control-plane & diagnostic routers
    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(platform_roles.router)
    app.include_router(users.router)
    app.include_router(external_apps.router)
    app.include_router(platforms.router)
    app.include_router(external_roles.router)

    # Serve compiled Vue 3 + Naive UI SPA when present (Phase 4 unified deployment)
    static_dir = cfg.resolved_static_dir
    index_file = static_dir / "index.html"
    if index_file.is_file():
        assets_dir = static_dir / "assets"
        if assets_dir.is_dir():
            app.mount("/assets", StaticFiles(directory=assets_dir), name="spa-assets")

        @app.get("/{full_path:path}", include_in_schema=False)
        async def serve_spa(full_path: str) -> FileResponse:
            candidate = (static_dir / full_path).resolve()
            if (
                full_path
                and candidate.is_file()
                and static_dir in candidate.parents
            ):
                return FileResponse(candidate)
            return FileResponse(index_file)

    return app


app = create_app()
