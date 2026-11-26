from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import select

from fieldscope.auth_engine.cache import CachedToken
from fieldscope.core.config import Settings
from fieldscope.db.base import utc_now
from fieldscope.db.models import Platform, PlatformTokenState
from fieldscope.main import create_app
from fieldscope.policy_engine.expr import UnsafeExpressionError, evaluate_expr
from tests.conftest import login_and_get_headers


@asynccontextmanager
async def _sec_client(
    handler: Any,
    *,
    settings_overrides: dict[str, Any] | None = None,
) -> AsyncIterator[tuple[httpx.AsyncClient, Any]]:
    upstream_http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    cfg_kwargs: dict[str, Any] = {
        "database_url": "sqlite+aiosqlite:///:memory:",
        "secret_key": "security-test-jwt-secret-key-at-least-32-bytes",
        "encryption_key": "security-test-aes-gcm-encryption-key",
        "bootstrap_admin_username": "admin",
        "bootstrap_admin_password": "AdminPassword123!",
    }
    if settings_overrides:
        cfg_kwargs.update(settings_overrides)
    app = create_app(Settings(**cfg_kwargs), http_client=upstream_http)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            yield client, app
    await upstream_http.aclose()


@pytest.mark.asyncio
async def test_h1_h2_h3_path_injection_specificity_and_fail_closed_governance() -> None:
    seen_requests: list[httpx.Request] = []

    def mock_upstream(request: httpx.Request) -> httpx.Response:
        seen_requests.append(request)
        path = request.url.path
        if path == "/wrapped":
            return httpx.Response(200, json={"items": [{"owner": "bob"}, {"owner": "eve"}]})
        if path == "/plain-text":
            return httpx.Response(
                200, content=b"plain secret text", headers={"content-type": "text/plain"}
            )
        if path == "/error-json":
            return httpx.Response(500, json={"debug_secret": "db-password", "owner": "eve"})
        if path == "/raw-echo":
            return httpx.Response(
                200,
                content=b"raw-bytes-ok",
                headers={"content-type": "application/octet-stream", "X-Upstream-Id": "up-77"},
            )
        return httpx.Response(
            200,
            json={"ok": True, "path": path, "raw_path": request.url.raw_path.decode()},
            headers={"X-Upstream-Id": "up-42"},
        )

    async with _sec_client(mock_upstream) as (c, _app):
        admin_h = await login_and_get_headers(c)
        pid = (
            await c.post(
                "/api/v1/admin/platforms",
                headers=admin_h,
                json={"code": "up", "name": "Up", "base_url": "https://up.local"},
            )
        ).json()["id"]

        async def add_ep(code: str, method: str, path: str, **extra: Any) -> int:
            r = await c.post(
                f"/api/v1/admin/platforms/{pid}/endpoints",
                headers=admin_h,
                json={"code": code, "name": code, "method": method, "path_pattern": path, **extra},
            )
            assert r.status_code == 201, r.text
            return r.json()["id"]

        # Register wildcard/param endpoint BEFORE static /items/export (H2)
        ep_item = await add_ep("get_item", "GET", "/items/{id}")
        await add_ep("export_items", "GET", "/items/export")
        ep_wrapped = await add_ep("wrapped", "GET", "/wrapped")
        ep_plain = await add_ep("plain", "GET", "/plain-text")
        ep_err = await add_ep("err_json", "GET", "/error-json")
        ep_post = await add_ep("create_item", "POST", "/items")
        ep_raw = await add_ep("raw_echo", "GET", "/raw-echo")

        # Route collision detection (H2)
        dup_route = await c.post(
            f"/api/v1/admin/platforms/{pid}/endpoints",
            headers=admin_h,
            json={
                "code": "dup_item",
                "name": "dup",
                "method": "GET",
                "path_pattern": "/items/{other}",
            },
        )
        assert dup_route.status_code == 409

        # Cross-platform MCP tool name collision check
        pid2 = (
            await c.post(
                "/api/v1/admin/platforms",
                headers=admin_h,
                json={"code": "up2", "name": "Up2", "base_url": "https://up2.local"},
            )
        ).json()["id"]
        dup_tool = await c.post(
            f"/api/v1/admin/platforms/{pid2}/endpoints",
            headers=admin_h,
            json={
                "code": "other",
                "name": "other",
                "method": "GET",
                "path_pattern": "/other",
                "expose_as_mcp": True,
                "mcp_tool_name": "up_get_item",
            },
        )
        assert dup_tool.status_code == 409

        # External role with policies (NO policy for export_items!)
        rid = (
            await c.post(
                "/api/v1/admin/external-roles",
                headers=admin_h,
                json={"code": "sec_role", "name": "Sec Role"},
            )
        ).json()["id"]

        for eid, extra in [
            (ep_item, {}),
            (ep_raw, {}),
            (
                ep_wrapped,
                {"row_filter": {"list_path": "data.items", "expr": "row.owner == user.username"}},
            ),
            (
                ep_plain,
                {"field_rules": {"mode": "allowlist", "fields": ["id"]}},
            ),
            (
                ep_err,
                {"field_rules": {"mode": "allowlist", "fields": ["id"]}},
            ),
            (
                ep_post,
                {"request_rules": {"enforce": {"body.tenant": "acme"}}},
            ),
        ]:
            pr = await c.post(
                f"/api/v1/admin/external-roles/{rid}/policies",
                headers=admin_h,
                json={"platform_id": pid, "endpoint_id": eid, **extra},
            )
            assert pr.status_code == 201, pr.text

        bob_id = (
            await c.post(
                "/api/v1/admin/users",
                headers=admin_h,
                json={
                    "username": "bob",
                    "password": "BobPassword123!",
                    "external_role_ids": [rid],
                },
            )
        ).json()["id"]
        bob_key = (
            await c.post(
                f"/api/v1/admin/users/{bob_id}/api-keys", headers=admin_h, json={"name": "k"}
            )
        ).json()["plain_key"]
        bob_h = {"Authorization": f"Bearer {bob_key}"}

        # H2: /items/export must match export_items (more specific) and be DENIED (403)
        r_export = await c.get("/gateway/up/items/export", headers=bob_h)
        assert r_export.status_code == 403

        # H1: Path injection via MCP args must be blocked without touching upstream
        seen_requests.clear()
        r_inj = await c.post(
            "/mcp",
            headers=bob_h,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "up_get_item", "arguments": {"id": "../admin/delete?all=1#"}},
            },
        )
        assert r_inj.status_code == 200
        assert r_inj.json()["error"]["code"] == -32000
        assert seen_requests == []

        # H1: Legitimate MCP path param with spaces is URL-encoded safely
        r_ok_mcp = await c.post(
            "/mcp",
            headers=bob_h,
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "up_get_item", "arguments": {"id": "PROJ 123"}},
            },
        )
        assert r_ok_mcp.status_code == 200
        assert "result" in r_ok_mcp.json()
        assert seen_requests[-1].url.raw_path == b"/items/PROJ%20123"

        # H1: Encoded traversal in HTTP proxy path rejected with 400
        r_trav = await c.get("/gateway/up/items/%2e%2e", headers=bob_h)
        assert r_trav.status_code == 400

        # H3: Missing list_path in row_filter fails closed (502), never leaks eve's data
        r_wrap = await c.get("/gateway/up/wrapped", headers=bob_h)
        assert r_wrap.status_code == 502
        assert "fail-closed" in r_wrap.json()["detail"].lower()

        # H3: Non-JSON upstream response fails closed when field governance active
        r_plain = await c.get("/gateway/up/plain-text", headers=bob_h)
        assert r_plain.status_code == 502

        # H3: Non-2xx upstream JSON error is sanitized when governance active
        r_err = await c.get("/gateway/up/error-json", headers=bob_h)
        assert r_err.status_code == 500
        assert "debug_secret" not in r_err.text
        assert r_err.json()["upstream_status"] == 500

        # H3: body.* enforce on non-dict JSON body (list) fails closed (400)
        r_bad_body = await c.post("/gateway/up/items", headers=bob_h, json=[{"a": 1}])
        assert r_bad_body.status_code == 400

        # Proxy hygiene: Cookie stripped, safe upstream headers preserved, raw binary preserved
        seen_requests.clear()
        r_raw = await c.get(
            "/gateway/up/raw-echo",
            headers={**bob_h, "Cookie": "session=secret-cookie"},
        )
        assert r_raw.status_code == 200
        assert r_raw.content == b"raw-bytes-ok"
        assert r_raw.headers.get("X-Upstream-Id") == "up-77"
        assert "cookie" not in {k.lower() for k in seen_requests[-1].headers}


@pytest.mark.asyncio
async def test_h4_privilege_escalation_blocked_for_users_and_platform_roles() -> None:
    async with _sec_client(lambda _req: httpx.Response(200)) as (c, _app):
        admin_h = await login_and_get_headers(c)
        all_users = (await c.get("/api/v1/admin/users", headers=admin_h)).json()
        admin_id = next(u["id"] for u in all_users if u["username"] == "admin")
        all_roles = (await c.get("/api/v1/admin/platform-roles", headers=admin_h)).json()
        super_role_id = next(r["id"] for r in all_roles if r["code"] == "super_admin")

        # Role with ONLY user:write and user:read
        hr_role_id = (
            await c.post(
                "/api/v1/admin/platform-roles",
                headers=admin_h,
                json={
                    "code": "hr_only",
                    "name": "HR",
                    "permission_codes": ["user:read", "user:write"],
                },
            )
        ).json()["id"]
        # Role with ONLY platform_role:write and platform_role:read
        rbac_role_id = (
            await c.post(
                "/api/v1/admin/platform-roles",
                headers=admin_h,
                json={
                    "code": "role_mgr",
                    "name": "Role Manager",
                    "permission_codes": ["platform_role:read", "platform_role:write"],
                },
            )
        ).json()["id"]

        hr_id = (
            await c.post(
                "/api/v1/admin/users",
                headers=admin_h,
                json={
                    "username": "hr_user",
                    "password": "HrPassword123!",
                    "platform_role_ids": [hr_role_id],
                },
            )
        ).json()["id"]
        rm_id = (
            await c.post(
                "/api/v1/admin/users",
                headers=admin_h,
                json={
                    "username": "role_user",
                    "password": "RmPassword123!",
                    "platform_role_ids": [rbac_role_id],
                },
            )
        ).json()["id"]
        assert rm_id > 0

        hr_h = await login_and_get_headers(c, "hr_user", "HrPassword123!")
        rm_h = await login_and_get_headers(c, "role_user", "RmPassword123!")

        # hr_user cannot elevate self to superuser
        assert (
            await c.patch(f"/api/v1/admin/users/{hr_id}", headers=hr_h, json={"is_superuser": True})
        ).status_code == 403
        # hr_user cannot create a superuser
        assert (
            await c.post(
                "/api/v1/admin/users",
                headers=hr_h,
                json={"username": "evil_su", "password": "Password123!", "is_superuser": True},
            )
        ).status_code == 403
        # hr_user cannot assign super_admin or a role with permissions they lack
        assert (
            await c.put(
                f"/api/v1/admin/users/{hr_id}/platform-roles",
                headers=hr_h,
                json={"role_ids": [super_role_id]},
            )
        ).status_code == 403
        assert (
            await c.put(
                f"/api/v1/admin/users/{hr_id}/platform-roles",
                headers=hr_h,
                json={"role_ids": [rbac_role_id]},
            )
        ).status_code == 403
        # hr_user cannot modify, delete, or mint API keys for superuser
        assert (
            await c.patch(
                f"/api/v1/admin/users/{admin_id}", headers=hr_h, json={"password": "Hacked123!"}
            )
        ).status_code == 403
        assert (await c.delete(f"/api/v1/admin/users/{admin_id}", headers=hr_h)).status_code == 403
        assert (
            await c.post(
                f"/api/v1/admin/users/{admin_id}/api-keys", headers=hr_h, json={"name": "stolen"}
            )
        ).status_code == 403

        # role_user cannot create a platform role granting permissions they don't hold
        assert (
            await c.post(
                "/api/v1/admin/platform-roles",
                headers=rm_h,
                json={
                    "code": "escalated",
                    "name": "Escalated",
                    "permission_codes": ["platform_role:write", "user:write"],
                },
            )
        ).status_code == 403
        # role_user cannot modify or delete hr_only (holds user:write)
        assert (
            await c.patch(
                f"/api/v1/admin/platform-roles/{hr_role_id}",
                headers=rm_h,
                json={"name": "Tampered"},
            )
        ).status_code == 403
        assert (
            await c.delete(f"/api/v1/admin/platform-roles/{hr_role_id}", headers=rm_h)
        ).status_code == 403

        # Low fix: UserUpdate can explicitly clear email to None
        u_id = (
            await c.post(
                "/api/v1/admin/users",
                headers=admin_h,
                json={"username": "clearable", "password": "Password123!", "email": "a@b.com"},
            )
        ).json()["id"]
        cleared = await c.patch(
            f"/api/v1/admin/users/{u_id}", headers=admin_h, json={"email": None}
        )
        assert cleared.status_code == 200
        assert cleared.json()["email"] is None


def test_h5_insecure_defaults_refused_in_production() -> None:
    with pytest.raises(RuntimeError, match="insecure defaults"):
        create_app(Settings(environment="prod"))

    # Proper production secrets pass validation
    app = create_app(
        Settings(
            environment="prod",
            database_url="sqlite+aiosqlite:///:memory:",
            secret_key="prod-very-strong-random-jwt-secret-key-64-chars-long-xxxxxxxx",
            encryption_key="prod-very-strong-encryption-master-key",
            bootstrap_admin_password="ProdStrongPassword!2026",
        )
    )
    assert app is not None


@pytest.mark.asyncio
async def test_h6_upstream_mcp_initialize_session_reinit_and_gateway_protocol() -> None:
    init_count = 0
    expired_once = False
    seen_methods: list[tuple[str, str | None]] = []

    def mock_mcp(request: httpx.Request) -> httpx.Response:
        nonlocal init_count, expired_once
        rpc = json.loads(request.content.decode("utf-8"))
        method = rpc.get("method")
        sid = request.headers.get("mcp-session-id")
        seen_methods.append((method, sid))

        if method == "initialize":
            init_count += 1
            return httpx.Response(
                200,
                headers={"Mcp-Session-Id": f"sess-{init_count}"},
                json={
                    "jsonrpc": "2.0",
                    "id": rpc["id"],
                    "result": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "StatefulMCP", "version": "1.0"},
                    },
                },
            )
        if method == "notifications/initialized":
            return httpx.Response(202)
        if method == "tools/list":
            if sid != f"sess-{init_count}":
                return httpx.Response(404, text="Missing or invalid session")
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": rpc["id"],
                    "result": {
                        "tools": [
                            {
                                "name": "echo_data",
                                "description": "Echo data",
                                "inputSchema": {"type": "object", "properties": {}},
                            }
                        ]
                    },
                },
            )
        if method == "tools/call":
            if not expired_once:
                expired_once = True
                return httpx.Response(404, text="Session expired")
            assert sid == "sess-2"
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": rpc["id"],
                    "result": {
                        "content": [
                            {"type": "text", "text": json.dumps({"ok": True, "secret": "hide"})}
                        ]
                    },
                },
            )
        return httpx.Response(404)

    async with _sec_client(mock_mcp) as (c, _app):
        admin_h = await login_and_get_headers(c)

        # Legacy SSE transport is rejected by schema
        bad_sse = await c.post(
            "/api/v1/admin/platforms",
            headers=admin_h,
            json={
                "code": "legacy_sse",
                "name": "Legacy",
                "protocol_type": "mcp",
                "base_url": "https://mcp.local/sse",
                "mcp_transport": "sse",
            },
        )
        assert bad_sse.status_code == 422

        pid = (
            await c.post(
                "/api/v1/admin/platforms",
                headers=admin_h,
                json={
                    "code": "stateful",
                    "name": "Stateful MCP",
                    "protocol_type": "mcp",
                    "base_url": "https://mcp.stateful.local/mcp",
                    "mcp_transport": "streamable_http",
                },
            )
        ).json()["id"]

        # Sync triggers initialize -> notifications/initialized -> tools/list with Mcp-Session-Id
        sync_resp = await c.post(f"/api/v1/admin/platforms/{pid}/sync-mcp-tools", headers=admin_h)
        assert sync_resp.status_code == 200
        ep_id = sync_resp.json()[0]["id"]
        assert init_count == 1
        assert ("tools/list", "sess-1") in seen_methods

        # Grant policy with field allowlist
        rid = (
            await c.post(
                "/api/v1/admin/external-roles", headers=admin_h, json={"code": "mr", "name": "MR"}
            )
        ).json()["id"]
        await c.post(
            f"/api/v1/admin/external-roles/{rid}/policies",
            headers=admin_h,
            json={
                "platform_id": pid,
                "endpoint_id": ep_id,
                "field_rules": {"mode": "allowlist", "fields": ["ok"]},
            },
        )
        uid = (
            await c.post(
                "/api/v1/admin/users",
                headers=admin_h,
                json={
                    "username": "mcpuser",
                    "password": "Password123!",
                    "external_role_ids": [rid],
                },
            )
        ).json()["id"]
        ukey = (
            await c.post(f"/api/v1/admin/users/{uid}/api-keys", headers=admin_h, json={"name": "k"})
        ).json()["plain_key"]
        uh = {"Authorization": f"Bearer {ukey}"}

        # Call tool -> first gets 404 session expired -> auto re-inits sess-2 -> succeeds!
        call_resp = await c.post(
            "/mcp",
            headers=uh,
            json={
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {"name": "stateful_echo_data", "arguments": {}},
            },
        )
        assert call_resp.status_code == 200
        out = json.loads(call_resp.json()["result"]["content"][0]["text"])
        assert out == {"ok": True}
        assert init_count == 2

        # Gateway /mcp polish: arbitrary notifications -> 202, GET -> 405, DELETE -> 204
        notif = await c.post(
            "/mcp",
            headers=uh,
            json={"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {}},
        )
        assert notif.status_code == 202
        assert (await c.get("/mcp", headers=uh)).status_code == 405
        assert (await c.delete("/mcp", headers=uh)).status_code == 204


@pytest.mark.asyncio
async def test_delegation_scoping_header_stripping_expr_validation_and_login_rate_limit() -> None:
    seen_headers: list[dict[str, str]] = []

    def mock_upstream(request: httpx.Request) -> httpx.Response:
        seen_headers.append(dict(request.headers))
        return httpx.Response(200, json={"ok": True})

    async with _sec_client(
        mock_upstream,
        settings_overrides={
            "login_rate_limit_max_attempts": 3,
            "login_rate_limit_window_seconds": 60,
        },
    ) as (c, _app):
        admin_h = await login_and_get_headers(c)
        pid = (
            await c.post(
                "/api/v1/admin/platforms",
                headers=admin_h,
                json={"code": "svc", "name": "Svc", "base_url": "https://svc.local"},
            )
        ).json()["id"]
        ep_id = (
            await c.post(
                f"/api/v1/admin/platforms/{pid}/endpoints",
                headers=admin_h,
                json={"code": "ping", "name": "Ping", "method": "GET", "path_pattern": "/ping"},
            )
        ).json()["id"]
        rid = (
            await c.post(
                "/api/v1/admin/external-roles", headers=admin_h, json={"code": "r1", "name": "R1"}
            )
        ).json()["id"]

        # Invalid/unsafe policy expression rejected at save time (422)
        bad_pol = await c.post(
            f"/api/v1/admin/external-roles/{rid}/policies",
            headers=admin_h,
            json={
                "platform_id": pid,
                "endpoint_id": ep_id,
                "row_filter": {"list_path": "", "expr": "__import__('os').system('id')"},
            },
        )
        assert bad_pol.status_code == 422

        # DoS expression guard: string multiplication blocked
        with pytest.raises(UnsafeExpressionError):
            evaluate_expr("'x' * 1000000", {})

        await c.post(
            f"/api/v1/admin/external-roles/{rid}/policies",
            headers=admin_h,
            json={"platform_id": pid, "endpoint_id": ep_id},
        )

        alice_id = (
            await c.post(
                "/api/v1/admin/users",
                headers=admin_h,
                json={"username": "alice", "password": "Password123!", "external_role_ids": [rid]},
            )
        ).json()["id"]
        bob_id = (
            await c.post(
                "/api/v1/admin/users",
                headers=admin_h,
                json={"username": "bob", "password": "Password123!", "external_role_ids": [rid]},
            )
        ).json()["id"]

        # Create scoped ExternalApp allowing ONLY alice via custom identity header
        app_key = (
            await c.post(
                "/api/v1/admin/external-apps",
                headers=admin_h,
                json={
                    "app_code": "scoped_app",
                    "name": "Scoped App",
                    "user_identity_header": "X-Custom-User",
                    "allowed_user_ids": [alice_id],
                },
            )
        ).json()["plain_key"]

        # Allowed user succeeds AND custom identity header is stripped before upstream
        ok = await c.get(
            "/gateway/svc/ping",
            headers={"Authorization": f"Bearer {app_key}", "X-Custom-User": "alice"},
        )
        assert ok.status_code == 200
        assert "x-custom-user" not in {k.lower() for k in seen_headers[-1]}

        # Out-of-scope user (bob) is rejected (403)
        denied = await c.get(
            "/gateway/svc/ping",
            headers={"Authorization": f"Bearer {app_key}", "X-Custom-User": "bob"},
        )
        assert denied.status_code == 403

        # Numeric ID fallback is removed: passing alice's numeric id must not match alice
        by_id = await c.get(
            "/gateway/svc/ping",
            headers={"Authorization": f"Bearer {app_key}", "X-Custom-User": str(alice_id)},
        )
        assert by_id.status_code == 403
        assert bob_id != alice_id

        # Login rate limiter triggers 429 after 3 failed attempts
        for _ in range(3):
            r = await c.post(
                "/api/v1/admin/auth/login",
                json={"username": "alice", "password": "WrongPassword!"},
            )
            assert r.status_code == 401
        r4 = await c.post(
            "/api/v1/admin/auth/login",
            json={"username": "alice", "password": "Password123!"},
        )
        assert r4.status_code == 429


@pytest.mark.asyncio
async def test_rotating_refresh_token_and_single_use_oauth_state() -> None:
    seen_refresh_tokens: list[str] = []

    def mock_idp(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/oauth/token":
            body = request.content.decode()
            if "grant_type=authorization_code" in body:
                return httpx.Response(
                    200,
                    json={
                        "access_token": "at-v1",
                        "refresh_token": "rt-v1",
                        "expires_in": 3600,
                    },
                )
            if "grant_type=refresh_token" in body:
                rt = body.split("refresh_token=")[1].split("&")[0]
                seen_refresh_tokens.append(rt)
                return httpx.Response(
                    200,
                    json={
                        "access_token": "at-v3",
                        "refresh_token": "rt-v3",
                        "expires_in": 3600,
                    },
                )
        return httpx.Response(200, json={"auth": request.headers.get("Authorization")})

    async with _sec_client(mock_idp) as (c, app):
        admin_h = await login_and_get_headers(c)
        pid = (
            await c.post(
                "/api/v1/admin/platforms",
                headers=admin_h,
                json={"code": "idp", "name": "IdP", "base_url": "https://idp.local"},
            )
        ).json()["id"]
        await c.put(
            f"/api/v1/admin/platforms/{pid}/auth",
            headers=admin_h,
            json={
                "auth_type": "oauth2",
                "grant_type": "authorization_code",
                "client_id": "cid",
                "client_secret": "csec",
                "authorize_url": "https://idp.local/oauth/authorize",
                "token_url": "https://idp.local/oauth/token",
                "redirect_uri": "https://fs.local/cb",
            },
        )
        state = (
            await c.get(f"/api/v1/admin/platforms/{pid}/auth/oauth/authorize-url", headers=admin_h)
        ).json()["state"]

        # First callback succeeds
        cb1 = await c.post(
            f"/api/v1/admin/platforms/{pid}/auth/oauth/callback",
            headers=admin_h,
            json={"code": "code-1", "state": state},
        )
        assert cb1.status_code == 200

        # Replaying the exact same OAuth state is rejected (single-use)
        cb2 = await c.post(
            f"/api/v1/admin/platforms/{pid}/auth/oauth/callback",
            headers=admin_h,
            json={"code": "code-1", "state": state},
        )
        assert cb2.status_code == 400

        # Simulate another worker rotating refresh_token in DB to "rt-v2" while local cache
        # still holds stale "rt-v1" and expired access token
        await app.state.auth_engine._cache.set(
            f"platform:{pid}:token",
            CachedToken(
                access_token="at-v1",
                refresh_token="rt-v1",
                token_type="Bearer",
                expires_at=utc_now() - timedelta(seconds=10),
            ),
        )
        async with app.state.db.session_factory() as db:
            ts = await db.scalar(
                select(PlatformTokenState).where(PlatformTokenState.platform_id == pid)
            )
            assert ts is not None
            ts.refresh_token_encrypted = app.state.cipher.encrypt_str(
                "rt-v2", aad=f"platform:{pid}:token"
            )
            ts.expires_at = utc_now() - timedelta(seconds=10)
            await db.commit()

            platform = await db.scalar(select(Platform).where(Platform.id == pid))
            assert platform is not None
            inj = await app.state.auth_engine.get_injection(db, platform)
            assert inj.raw_token == "at-v3"

        # Must have used the latest DB refresh_token "rt-v2", NOT stale cached "rt-v1"!
        assert seen_refresh_tokens == ["rt-v2"]
