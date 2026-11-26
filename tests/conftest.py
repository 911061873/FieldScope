from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest

from fieldscope.core.config import Settings
from fieldscope.main import create_app


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    """Provide an isolated async HTTP client backed by an in-memory SQLite database."""
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret_key="test-jwt-secret-key-for-unit-tests-at-least-32-bytes",
        encryption_key="test-aes-gcm-encryption-key",
        bootstrap_admin_username="admin",
        bootstrap_admin_password="AdminPassword123!",
    )
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:
            yield ac


async def login_and_get_headers(
    client: httpx.AsyncClient,
    username: str = "admin",
    password: str = "AdminPassword123!",
) -> dict[str, str]:
    resp = await client.post(
        "/api/v1/admin/auth/login",
        json={"username": username, "password": password},
    )
    assert resp.status_code == 200, resp.text
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
