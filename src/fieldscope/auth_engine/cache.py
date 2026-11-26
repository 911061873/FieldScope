from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol


@dataclass(frozen=True)
class CachedToken:
    access_token: str
    refresh_token: str | None
    token_type: str
    expires_at: datetime | None


class TokenCacheBackend(Protocol):
    """Pluggable token cache + single-flight lock backend (InMemory / Redis)."""

    async def get(self, key: str) -> CachedToken | None: ...

    async def set(self, key: str, value: CachedToken) -> None: ...

    async def delete(self, key: str) -> None: ...

    @asynccontextmanager
    def lock(self, key: str) -> AsyncIterator[None]: ...


class InMemoryTokenCache:
    """Single-process async token cache with per-key asyncio.Lock single-flight coordination."""

    def __init__(self) -> None:
        self._store: dict[str, CachedToken] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    async def get(self, key: str) -> CachedToken | None:
        return self._store.get(key)

    async def set(self, key: str, value: CachedToken) -> None:
        self._store[key] = value

    async def delete(self, key: str) -> None:
        self._store.pop(key, None)

    @asynccontextmanager
    async def lock(self, key: str) -> AsyncIterator[None]:
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            yield
