from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from sqlalchemy import select

from fieldscope.auth_engine.jsonpath import extract_json_path
from fieldscope.core.config import Settings
from fieldscope.db.base import utc_now
from fieldscope.db.models import Platform, PlatformTokenState
from fieldscope.main import create_app
from fieldscope.schemas.platform_auth import MASKED_SECRET_PLACEHOLDER
from tests.conftest import login_and_get_headers


@asynccontextmanager
async def _app_client_with_mock_upstream(
    handler: httpx.AsyncBaseTransport | object,
) -> AsyncIterator[tuple[httpx.AsyncClient, object]]:
    transport = (
        handler
        if isinstance(handler, httpx.AsyncBaseTransport)
        else httpx.MockTransport(handler)  # type: ignore[arg-type]
    )
    upstream_http = httpx.AsyncClient(transport=transport)
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret_key="phase2-test-jwt-secret-key-at-least-32-bytes-long",
        encryption_key="phase2-test-aes-gcm-encryption-key",
        bootstrap_admin_username="admin",
        bootstrap_admin_password="AdminPassword123!",
    )
    app = create_app(settings, http_client=upstream_http)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            yield client, app
    await upstream_http.aclose()


def test_jsonpath_extractor() -> None:
    sample = {
        "data": {"items": [{"token": "tok-1"}], "meta": {"expires_in": 7200}},
        "errcode": 40001,
    }
    assert extract_json_path(sample, "$.data.items[0].token") == "tok-1"
    assert extract_json_path(sample, "data.meta.expires_in") == 7200
    assert extract_json_path(sample, "errcode") == 40001
    assert extract_json_path(sample, "$.missing.field", default="fallback") == "fallback"


@pytest.mark.asyncio
async def test_static_auth_header_query_and_secret_preservation() -> None:
    captured: list[httpx.Request] = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(
            200,
            json={
                "auth_header": request.headers.get("X-Custom-Auth"),
                "query_token": request.url.params.get("api_key"),
            },
        )

    async with _app_client_with_mock_upstream(mock_handler) as (client, _app):
        headers = await login_and_get_headers(client)

        plat_resp = await client.post(
            "/api/v1/admin/platforms",
            headers=headers,
            json={
                "code": "erp",
                "name": "Internal ERP",
                "protocol_type": "api",
                "base_url": "https://erp.mock.local",
            },
        )
        assert plat_resp.status_code == 201
        pid = plat_resp.json()["id"]

        # 1. Configure static header auth
        put_resp = await client.put(
            f"/api/v1/admin/platforms/{pid}/auth",
            headers=headers,
            json={
                "auth_type": "static",
                "location": "header",
                "param_name": "X-Custom-Auth",
                "value": "secret-static-token-999",
                "value_prefix": "Token ",
            },
        )
        assert put_resp.status_code == 200
        assert put_resp.json()["config"]["value"] == MASKED_SECRET_PLACEHOLDER

        # Live test verifies header injection
        test1 = await client.post(
            f"/api/v1/admin/platforms/{pid}/auth/test",
            headers=headers,
            json={"method": "GET", "path": "/v1/ping"},
        )
        assert test1.status_code == 200
        assert test1.json()["ok"] is True
        assert test1.json()["response_preview"]["auth_header"] == "Token secret-static-token-999"

        # 2. Switch location to query while sending masked placeholder -> must preserve old secret!
        put_resp2 = await client.put(
            f"/api/v1/admin/platforms/{pid}/auth",
            headers=headers,
            json={
                "auth_type": "static",
                "location": "query",
                "param_name": "api_key",
                "value": MASKED_SECRET_PLACEHOLDER,
                "value_prefix": "",
            },
        )
        assert put_resp2.status_code == 200

        test2 = await client.post(
            f"/api/v1/admin/platforms/{pid}/auth/test",
            headers=headers,
            json={"method": "GET", "path": "/v1/ping"},
        )
        assert test2.status_code == 200
        assert test2.json()["response_preview"]["query_token"] == "secret-static-token-999"


@pytest.mark.asyncio
async def test_oauth2_client_credentials_cache_leeway_and_401_replay() -> None:
    token_calls = 0
    current_valid_token = ""
    force_first_data_401 = True

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal token_calls, current_valid_token, force_first_data_401

        if request.url.path == "/oauth/token":
            token_calls += 1
            # Verify HTTP Basic auth header was sent
            expected_basic = base64.b64encode(b"cid-123:csec-456").decode("ascii")
            assert request.headers.get("Authorization") == f"Basic {expected_basic}"
            current_valid_token = f"oauth-tok-{token_calls}"
            return httpx.Response(
                200,
                json={
                    "access_token": current_valid_token,
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            )

        if request.url.path == "/api/orders":
            auth_hdr = request.headers.get("Authorization")
            if force_first_data_401 and auth_hdr == "Bearer oauth-tok-1":
                force_first_data_401 = False
                return httpx.Response(401, json={"error": "token_revoked_early"})
            if auth_hdr != f"Bearer {current_valid_token}":
                return httpx.Response(401, json={"error": "invalid_token"})
            return httpx.Response(200, json={"ok": True, "used_token": current_valid_token})

        return httpx.Response(404)

    async with _app_client_with_mock_upstream(mock_handler) as (client, _app):
        headers = await login_and_get_headers(client)
        plat = await client.post(
            "/api/v1/admin/platforms",
            headers=headers,
            json={
                "code": "jira_oauth",
                "name": "Jira OAuth2",
                "protocol_type": "api",
                "base_url": "https://oauth.mock.local",
            },
        )
        pid = plat.json()["id"]

        put_resp = await client.put(
            f"/api/v1/admin/platforms/{pid}/auth",
            headers=headers,
            json={
                "auth_type": "oauth2",
                "grant_type": "client_credentials",
                "client_id": "cid-123",
                "client_secret": "csec-456",
                "token_url": "https://oauth.mock.local/oauth/token",
                "scopes": ["read:issues"],
                "client_auth_method": "basic",
                "refresh_leeway_seconds": 60,
            },
        )
        assert put_resp.status_code == 200
        assert put_resp.json()["config"]["client_secret"] == MASKED_SECRET_PLACEHOLDER

        # First call fetches oauth-tok-1, hits simulated 401 -> refreshes to oauth-tok-2 -> replays!
        test_resp = await client.post(
            f"/api/v1/admin/platforms/{pid}/auth/test",
            headers=headers,
            json={"method": "GET", "path": "/api/orders"},
        )
        assert test_resp.status_code == 200
        data = test_resp.json()
        assert data["ok"] is True
        assert data["retried_after_refresh"] is True
        assert data["response_preview"]["used_token"] == "oauth-tok-2"
        assert token_calls == 2

        # Second call reuses cached oauth-tok-2 without hitting /oauth/token again
        test_resp2 = await client.post(
            f"/api/v1/admin/platforms/{pid}/auth/test",
            headers=headers,
            json={"method": "GET", "path": "/api/orders"},
        )
        assert test_resp2.status_code == 200
        assert test_resp2.json()["retried_after_refresh"] is False
        assert token_calls == 2

        # Inspect token status
        status_resp = await client.get(
            f"/api/v1/admin/platforms/{pid}/auth/token-status",
            headers=headers,
        )
        assert status_resp.status_code == 200
        assert status_resp.json()["has_access_token"] is True
        assert status_resp.json()["is_expired"] is False


@pytest.mark.asyncio
async def test_oauth2_authorization_code_flow_and_refresh_token_renewal() -> None:
    seen_grants: list[str] = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/oauth/token":
            form = parse_qs(request.content.decode("utf-8"))
            grant_type = form["grant_type"][0]
            seen_grants.append(grant_type)
            if grant_type == "authorization_code":
                assert form["code"][0] == "auth-code-xyz"
                return httpx.Response(
                    200,
                    json={
                        "access_token": "ac-token-v1",
                        "refresh_token": "rt-token-v1",
                        "expires_in": 300,
                    },
                )
            if grant_type == "refresh_token":
                assert form["refresh_token"][0] == "rt-token-v1"
                return httpx.Response(
                    200,
                    json={
                        "access_token": "ac-token-v2",
                        "refresh_token": "rt-token-v2",
                        "expires_in": 3600,
                    },
                )
        if request.url.path == "/api/me":
            return httpx.Response(200, json={"auth": request.headers.get("Authorization")})
        return httpx.Response(404)

    async with _app_client_with_mock_upstream(mock_handler) as (client, app):
        headers = await login_and_get_headers(client)
        plat = await client.post(
            "/api/v1/admin/platforms",
            headers=headers,
            json={
                "code": "feishu_oauth",
                "name": "Feishu Admin OAuth",
                "protocol_type": "api",
                "base_url": "https://feishu.mock.local",
            },
        )
        pid = plat.json()["id"]

        await client.put(
            f"/api/v1/admin/platforms/{pid}/auth",
            headers=headers,
            json={
                "auth_type": "oauth2",
                "grant_type": "authorization_code",
                "client_id": "app-id-1",
                "client_secret": "app-sec-1",
                "authorize_url": "https://feishu.mock.local/oauth/authorize",
                "token_url": "https://feishu.mock.local/oauth/token",
                "redirect_uri": "https://fieldscope.local/callback",
                "scopes": ["contact:read"],
                "refresh_leeway_seconds": 60,
            },
        )

        # Calling refresh before admin authorization yields 412 Precondition Failed
        pre = await client.post(f"/api/v1/admin/platforms/{pid}/auth/refresh", headers=headers)
        assert pre.status_code == 412

        # Step 1: Build authorize URL with signed state
        url_resp = await client.get(
            f"/api/v1/admin/platforms/{pid}/auth/oauth/authorize-url",
            headers=headers,
        )
        assert url_resp.status_code == 200
        auth_url = url_resp.json()["authorize_url"]
        state = url_resp.json()["state"]
        parsed_qs = parse_qs(urlparse(auth_url).query)
        assert parsed_qs["client_id"] == ["app-id-1"]
        assert parsed_qs["state"] == [state]

        # Tampered state is rejected
        bad_cb = await client.post(
            f"/api/v1/admin/platforms/{pid}/auth/oauth/callback",
            headers=headers,
            json={"code": "auth-code-xyz", "state": "tampered.state.token"},
        )
        assert bad_cb.status_code == 400

        # Step 2: Valid callback exchanges code for access_token + refresh_token
        cb_resp = await client.post(
            f"/api/v1/admin/platforms/{pid}/auth/oauth/callback",
            headers=headers,
            json={"code": "auth-code-xyz", "state": state},
        )
        assert cb_resp.status_code == 200
        assert cb_resp.json()["has_access_token"] is True
        assert cb_resp.json()["has_refresh_token"] is True

        # Step 3: Simulate token entering proactive refresh window & cache eviction (restart)
        await app.state.auth_engine._cache.delete(f"platform:{pid}:token")
        async with app.state.db.session_factory() as session:
            ts = await session.scalar(
                select(PlatformTokenState).where(PlatformTokenState.platform_id == pid)
            )
            assert ts is not None
            ts.expires_at = utc_now() + timedelta(seconds=10)  # < 60s leeway!
            await session.commit()

        # Next live request must automatically renew via refresh_token!
        live = await client.post(
            f"/api/v1/admin/platforms/{pid}/auth/test",
            headers=headers,
            json={"method": "GET", "path": "/api/me"},
        )
        assert live.status_code == 200
        assert live.json()["response_preview"]["auth"] == "Bearer ac-token-v2"
        assert seen_grants == ["authorization_code", "refresh_token"]


@pytest.mark.asyncio
async def test_custom_http_token_business_code_retry_and_refresh_request() -> None:
    login_calls = 0
    refresh_calls = 0
    active_token = ""

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal login_calls, refresh_calls, active_token

        if request.url.path == "/auth/custom-login":
            login_calls += 1
            body = json.loads(request.content.decode("utf-8"))
            assert body["appKey"] == "k-pub"
            assert body["appSecret"] == "s-priv-secret"
            active_token = "custom-tok-1"
            return httpx.Response(
                200,
                json={
                    "code": 0,
                    "data": {
                        "credentials": {
                            "token": active_token,
                            "refresh": "custom-rt-1",
                        },
                        "ttl": 3600,
                    },
                },
            )

        if request.url.path == "/auth/custom-refresh":
            refresh_calls += 1
            body = json.loads(request.content.decode("utf-8"))
            assert body["refreshToken"] == "custom-rt-1"
            active_token = "custom-tok-2"
            return httpx.Response(
                200,
                json={
                    "code": 0,
                    "data": {
                        "credentials": {"token": active_token, "refresh": "custom-rt-2"},
                        "ttl": 3600,
                    },
                },
            )

        if request.url.path == "/api/customers":
            tok = request.url.params.get("access_token")
            # Simulate domestic enterprise API returning HTTP 200 with code=40001 on stale token
            if tok == "custom-tok-1":
                return httpx.Response(200, json={"code": 40001, "msg": "token expired"})
            if tok == "custom-tok-2":
                return httpx.Response(200, json={"code": 0, "items": [{"id": 1, "name": "Acme"}]})
            return httpx.Response(200, json={"code": 40001, "msg": "unknown token"})

        return httpx.Response(404)

    async with _app_client_with_mock_upstream(mock_handler) as (client, _app):
        headers = await login_and_get_headers(client)
        plat = await client.post(
            "/api/v1/admin/platforms",
            headers=headers,
            json={
                "code": "wecom_like",
                "name": "Enterprise Custom API",
                "protocol_type": "api",
                "base_url": "https://wecom.mock.local",
            },
        )
        pid = plat.json()["id"]

        put_resp = await client.put(
            f"/api/v1/admin/platforms/{pid}/auth",
            headers=headers,
            json={
                "auth_type": "custom_http",
                "token_request": {
                    "method": "POST",
                    "url": "https://wecom.mock.local/auth/custom-login",
                    "body_type": "json",
                    "body": {"appKey": "k-pub", "appSecret": "{{ secret.app_secret }}"},
                },
                "refresh_request": {
                    "method": "POST",
                    "url": "https://wecom.mock.local/auth/custom-refresh",
                    "body_type": "json",
                    "body": {"refreshToken": "{{ token.refresh_token }}"},
                },
                "secrets": {"app_secret": "s-priv-secret"},
                "response_mapping": {
                    "access_token_path": "$.data.credentials.token",
                    "refresh_token_path": "$.data.credentials.refresh",
                    "expires_in_path": "$.data.ttl",
                },
                "inject_location": "query",
                "inject_name": "access_token",
                "inject_prefix": "",
                "invalid_rules": {
                    "http_statuses": [401],
                    "body_rules": [{"path": "$.code", "in_values": [40001, 42001]}],
                },
            },
        )
        assert put_resp.status_code == 200
        assert put_resp.json()["config"]["secrets"]["app_secret"] == MASKED_SECRET_PLACEHOLDER

        # First call gets custom-tok-1 -> hits HTTP 200 {code: 40001} -> triggers refresh_request ->
        # replays with custom-tok-2 -> returns {code: 0, items: [...]}!
        test_resp = await client.post(
            f"/api/v1/admin/platforms/{pid}/auth/test",
            headers=headers,
            json={"method": "GET", "path": "/api/customers"},
        )
        assert test_resp.status_code == 200
        res = test_resp.json()
        assert res["ok"] is True
        assert res["retried_after_refresh"] is True
        assert res["response_preview"]["code"] == 0
        assert res["response_preview"]["items"][0]["name"] == "Acme"
        assert login_calls == 1
        assert refresh_calls == 1


@pytest.mark.asyncio
async def test_single_flight_prevents_concurrent_refresh_storm() -> None:
    token_fetch_count = 0

    async def async_mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal token_fetch_count
        if request.url.path == "/token":
            token_fetch_count += 1
            await asyncio.sleep(0.05)  # Simulate network latency
            return httpx.Response(
                200,
                json={"access_token": f"sf-token-{token_fetch_count}", "expires_in": 3600},
            )
        return httpx.Response(404)

    async with _app_client_with_mock_upstream(async_mock_handler) as (client, app):
        headers = await login_and_get_headers(client)
        plat = await client.post(
            "/api/v1/admin/platforms",
            headers=headers,
            json={
                "code": "concurrent_api",
                "name": "Concurrent API",
                "protocol_type": "api",
                "base_url": "https://sf.mock.local",
            },
        )
        pid = plat.json()["id"]

        await client.put(
            f"/api/v1/admin/platforms/{pid}/auth",
            headers=headers,
            json={
                "auth_type": "oauth2",
                "grant_type": "client_credentials",
                "client_id": "sf-cid",
                "client_secret": "sf-sec",
                "token_url": "https://sf.mock.local/token",
            },
        )

        async def worker() -> str | None:
            async with app.state.db.session_factory() as session:
                platform = await session.scalar(select(Platform).where(Platform.id == pid))
                assert platform is not None
                inj = await app.state.auth_engine.get_injection(session, platform)
                return inj.raw_token

        # Launch 20 concurrent requests simultaneously against a cold cache
        results = await asyncio.gather(*(worker() for _ in range(20)))
        assert token_fetch_count == 1
        assert all(tok == "sf-token-1" for tok in results)
