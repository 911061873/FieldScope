from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from fastapi import Request
from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from fieldscope.db.base import Base


class DatabaseManager:
    """Encapsulates async SQLAlchemy engine & session factory (attached to FastAPI app.state)."""

    def __init__(self, database_url: str, echo: bool = False) -> None:
        self.database_url = database_url
        kwargs: dict[str, Any] = {"echo": echo}

        if database_url.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False}
            if ":memory:" in database_url:
                kwargs["poolclass"] = StaticPool

        self.engine: AsyncEngine = create_async_engine(database_url, **kwargs)

        if database_url.startswith("sqlite"):

            @event.listens_for(self.engine.sync_engine, "connect")
            def _enable_sqlite_fk(dbapi_connection: Any, _connection_record: Any) -> None:
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.close()

        self.session_factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
            bind=self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )

    async def create_tables(self) -> None:
        # Ensure all ORM models are registered in Base.metadata before create_all.
        from fieldscope.db import models as _models  # noqa: F401

        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def dispose(self) -> None:
        await self.engine.dispose()


async def get_db(request: Request) -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding an async DB session per request."""
    db_manager: DatabaseManager = request.app.state.db
    async with db_manager.session_factory() as session:
        yield session
