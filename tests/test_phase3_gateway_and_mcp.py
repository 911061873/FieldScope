from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
import pytest

from fieldscope.core.config import Settings
from fieldscope.field_engine.engine import MergedFieldRules, apply_field_rules
from fieldscope.main import create_app
from fieldscope.policy_engine.expr import UnsafeExpressionError, evaluate_expr
from tests.conftest import login_and_get_headers


@asynccontextmanager
async def _phase3_client(handler: object) -> AsyncIterator[httpx.AsyncClient]:
    upstream_http = httpx.AsyncClient(
        transport=httpx.MockTransport(handler)  # type: ignore[arg-type]
    )
    settings = Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret_key="phase3-test-jwt-secret-key-at-least-32-bytes-long",
        encryption_key="phase3-test-aes-gcm-encryption-key",
        bootstrap_admin_username="admin",
        bootstrap_admin_password="AdminPassword123!",
    )
    app = create_app(settings, http_client=upstream_http)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            yield client
    await upstream_http.aclose()


def test_safe_expr_evaluator_and_sandbox() -> None:
    ctx = {
        "query": {"limit": "25", "status": "open"},
        "user": {"username": "bob", "attributes": {"dept": "D01"}},
        "row": {"owner": "bob", "dept": "D02"},
    }
    assert evaluate_expr("query.limit == null || query.limit <= 50", ctx) is True
    assert (
        evaluate_expr("query.missing == null && query.status in ['open', 'pending']", ctx) is True
    )
    assert (
        evaluate_expr("row.owner == user.username || row.dept == user.attributes.dept", ctx) is True
    )
    assert evaluate_expr("query.limit > 50", ctx) is False

    # Disallowed unsafe constructs must raise UnsafeExpressionError
    with pytest.raises(UnsafeExpressionError):
        evaluate_expr("__import__('os').system('id')", ctx)
    with pytest.raises(UnsafeExpressionError):
        evaluate_expr("user.__class__", ctx)
    with pytest.raises(UnsafeExpressionError):
        evaluate_expr("(lambda x: x)(1)", ctx)


def test_field_engine_allowlist_denylist_and_transforms() -> None:
    payload = {
        "data": {
            "items": [
                {
                    "id": 1,
                    "name": "Alice",
                    "phone": "13812345678",
                    "email": "alice@example.com",
                    "id_card": "310101199001011234",
                    "secret_note": "top-secret",
                }
            ]
        }
    }
    res = apply_field_rules(
        payload,
        MergedFieldRules(
            mode="allowlist",
            fields=[
                "data.items[*].id",
                "data.items[*].name",
                "data.items[*].phone",
                "data.items[*].email",
                "data.items[*].id_card",
            ],
            transforms={
                "data.items[*].phone": "mask_phone",
                "data.items[*].email": "mask_email",
                "data.items[*].id_card": "hash",
            },
        ),
    )
    item = res.data["data"]["items"][0]
    assert "secret_note" not in item
    assert item["phone"] == "138****5678"
    assert item["email"] == "a***e@example.com"
    assert item["id_card"].startswith("sha256:")
    assert "data.items[*].secret_note" in res.pruned_fields
    assert sorted(res.transformed_fields) == [
        "data.items[*].email",
        "data.items[*].id_card",
        "data.items[*].phone",
    ]


@pytest.mark.asyncio
async def test_http_proxy_multi_role_merge_row_filter_field_mask_and_audit() -> None:
    upstream_received_regions: list[str | None] = []

    def mock_upstream(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/customers":
            assert request.headers.get("X-CRM-Key") == "crm-real-secret"
            upstream_received_regions.append(request.url.params.get("region"))
            return httpx.Response(
                200,
                json={
                    "data": {
                        "items": [
                            {
                                "id": 1,
                                "name": "Bob Account",
                                "owner": "bob",
                                "dept": "D02",
                                "phone": "13800138000",
                                "amount": 50000,
                                "internal_margin": 0.42,
                            },
                            {
                                "id": 2,
                                "name": "Dept Account",
                                "owner": "charlie",
                                "dept": "D01",
                                "phone": "13900139000",
                                "amount": 88000,
                                "internal_margin": 0.35,
                            },
                            {
                                "id": 3,
                                "name": "Other Region Account",
                                "owner": "dave",
                                "dept": "D99",
                                "phone": "13700137000",
                                "amount": 99000,
                                "internal_margin": 0.50,
                            },
                        ]
                    }
                },
            )
        return httpx.Response(404)

    async with _phase3_client(mock_upstream) as client:
        admin_h = await login_and_get_headers(client)

        # 1. Create CRM platform + static auth + endpoint
        plat = await client.post(
            "/api/v1/admin/platforms",
            headers=admin_h,
            json={
                "code": "crm",
                "name": "CRM",
                "protocol_type": "api",
                "base_url": "https://crm.mock.local",
            },
        )
        pid = plat.json()["id"]
        await client.put(
            f"/api/v1/admin/platforms/{pid}/auth",
            headers=admin_h,
            json={
                "auth_type": "static",
                "location": "header",
                "param_name": "X-CRM-Key",
                "value": "crm-real-secret",
            },
        )
        ep = await client.post(
            f"/api/v1/admin/platforms/{pid}/endpoints",
            headers=admin_h,
            json={
                "resource_type": "http_endpoint",
                "code": "list_customers",
                "name": "客户列表",
                "method": "GET",
                "path_pattern": "/api/v1/customers",
                "expose_as_mcp": True,
                "mcp_tool_name": "crm_list_customers",
            },
        )
        ep_id = ep.json()["id"]

        # 2. Create two External Roles with overlapping fields & conflicting phone transforms
        r1 = await client.post(
            "/api/v1/admin/external-roles",
            headers=admin_h,
            json={"code": "sales", "name": "销售角色"},
        )
        r1_id = r1.json()["id"]
        await client.post(
            f"/api/v1/admin/external-roles/{r1_id}/policies",
            headers=admin_h,
            json={
                "platform_id": pid,
                "endpoint_id": ep_id,
                "name": "销售客户查询",
                "effect": "allow",
                "priority": 100,
                "request_rules": {
                    "validate": [
                        {"expr": "query.limit == null || query.limit <= 50", "message": "超限"}
                    ],
                    "enforce": {"query.region": "{{ user.attributes.region }}"},
                },
                "row_filter": {"list_path": "data.items", "expr": "row.owner == user.username"},
                "field_rules": {
                    "mode": "allowlist",
                    "fields": [
                        "data.items[*].id",
                        "data.items[*].name",
                        "data.items[*].phone",
                    ],
                    "transforms": [{"path": "data.items[*].phone", "action": "mask_phone"}],
                },
            },
        )

        r2 = await client.post(
            "/api/v1/admin/external-roles",
            headers=admin_h,
            json={"code": "finance", "name": "财务角色"},
        )
        r2_id = r2.json()["id"]
        await client.post(
            f"/api/v1/admin/external-roles/{r2_id}/policies",
            headers=admin_h,
            json={
                "platform_id": pid,
                "endpoint_id": ep_id,
                "name": "财务客户金额查看",
                "effect": "allow",
                "priority": 90,
                "row_filter": {
                    "list_path": "data.items",
                    "expr": "row.dept == user.attributes.dept_id",
                },
                "field_rules": {
                    "mode": "allowlist",
                    "fields": [
                        "data.items[*].id",
                        "data.items[*].name",
                        "data.items[*].amount",
                        "data.items[*].phone",
                    ],
                    # Stricter transform than mask_phone -> security-first must pick redact!
                    "transforms": [{"path": "data.items[*].phone", "action": "redact"}],
                },
            },
        )

        # 3. Create user Bob assigned BOTH sales and finance external roles
        bob = await client.post(
            "/api/v1/admin/users",
            headers=admin_h,
            json={
                "username": "bob",
                "password": "BobPassword123!",
                "attributes": {"region": "east", "dept_id": "D01"},
                "external_role_ids": [r1_id, r2_id],
            },
        )
        bob_id = bob.json()["id"]
        bob_key = (
            await client.post(
                f"/api/v1/admin/users/{bob_id}/api-keys",
                headers=admin_h,
                json={"name": "bob-key"},
            )
        ).json()["plain_key"]

        # Validation violation (limit=100 > 50) -> 403
        denied = await client.get(
            "/gateway/crm/api/v1/customers?limit=100",
            headers={"Authorization": f"Bearer {bob_key}"},
        )
        assert denied.status_code == 403
        assert "超限" in denied.json()["detail"]

        # Valid call with spoofed ?region=west -> forced to region=east, union rows & fields!
        ok_resp = await client.get(
            "/gateway/crm/api/v1/customers?region=west&limit=20",
            headers={"Authorization": f"Bearer {bob_key}"},
        )
        assert ok_resp.status_code == 200
        assert "X-FieldScope-Trace-Id" in ok_resp.headers
        assert upstream_received_regions == ["east"]

        items = ok_resp.json()["data"]["items"]
        assert [row["id"] for row in items] == [1, 2]  # Row 3 filtered out!
        assert items[0]["amount"] == 50000  # Unioned from finance role
        assert items[0]["phone"] == "[REDACTED]"  # Strictest transform won!
        assert "internal_margin" not in items[0]  # Pruned!

        # Verify audit logs recorded both deny and allow with exact metadata
        audits = (
            await client.get("/api/v1/admin/audit-logs?username=bob", headers=admin_h)
        ).json()
        assert audits["total"] == 2
        latest = audits["items"][0]
        assert latest["decision"] == "allow"
        assert latest["protocol"] == "http"
        assert latest["enforced_params"] == {"query.region": "east"}
        assert latest["rows_before"] == 3
        assert latest["rows_after"] == 2
        assert "data.items[*].internal_margin" in latest["pruned_fields"]
        assert "data.items[*].phone" in latest["transformed_fields"]

        stats = (await client.get("/api/v1/admin/audit-logs/stats", headers=admin_h)).json()
        assert stats["total"] == 2
        assert stats["allowed"] == 1
        assert stats["denied"] == 1


@pytest.mark.asyncio
async def test_mcp_gateway_rest_to_mcp_and_upstream_mcp_sync_and_proxy() -> None:
    def mock_upstream(request: httpx.Request) -> httpx.Response:
        # 1) Upstream REST API for REST-to-MCP tool
        if request.url.host == "jira.mock.local" and request.url.path == "/rest/api/3/search":
            assert request.url.params.get("project") == "ALPHA"
            return httpx.Response(
                200,
                json={
                    "issues": [
                        {
                            "key": "ALPHA-1",
                            "summary": "Fix auth",
                            "reporter_email": "lead@corp.com",
                            "secret_cost": 9999,
                        }
                    ]
                },
            )

        # 2) Upstream Remote MCP Server (Streamable HTTP JSON-RPC 2.0)
        if request.url.host == "mcp.upstream.local":
            assert request.headers.get("Authorization") == "Bearer upstream-mcp-secret"
            rpc = json.loads(request.content.decode("utf-8"))
            if rpc["method"] == "tools/list":
                return httpx.Response(
                    200,
                    json={
                        "jsonrpc": "2.0",
                        "id": rpc["id"],
                        "result": {
                            "tools": [
                                {
                                    "name": "query_hr_staff",
                                    "description": "Query HR staff directory",
                                    "inputSchema": {
                                        "type": "object",
                                        "properties": {"dept": {"type": "string"}},
                                    },
                                },
                                {
                                    "name": "terminate_staff",
                                    "description": "Admin-only termination tool",
                                    "inputSchema": {"type": "object", "properties": {}},
                                },
                            ]
                        },
                    },
                )
            if rpc["method"] == "tools/call":
                assert rpc["params"]["name"] == "query_hr_staff"
                assert rpc["params"]["arguments"]["dept"] == "ENG"
                return httpx.Response(
                    200,
                    json={
                        "jsonrpc": "2.0",
                        "id": rpc["id"],
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": json.dumps(
                                        {
                                            "staff": [
                                                {
                                                    "name": "Alice",
                                                    "mobile": "13611112222",
                                                    "salary": 500000,
                                                }
                                            ]
                                        }
                                    ),
                                }
                            ]
                        },
                    },
                )
        return httpx.Response(404)

    async with _phase3_client(mock_upstream) as client:
        admin_h = await login_and_get_headers(client)

        # A. Create Jira REST platform + 2 endpoints (search & admin delete)
        jira_pid = (
            await client.post(
                "/api/v1/admin/platforms",
                headers=admin_h,
                json={
                    "code": "jira",
                    "name": "Jira",
                    "protocol_type": "api",
                    "base_url": "https://jira.mock.local",
                },
            )
        ).json()["id"]
        jira_search_ep = (
            await client.post(
                f"/api/v1/admin/platforms/{jira_pid}/endpoints",
                headers=admin_h,
                json={
                    "resource_type": "http_endpoint",
                    "code": "search",
                    "name": "搜索工单",
                    "method": "GET",
                    "path_pattern": "/rest/api/3/search",
                    "expose_as_mcp": True,
                    "mcp_tool_name": "jira_search_issues",
                },
            )
        ).json()["id"]
        await client.post(
            f"/api/v1/admin/platforms/{jira_pid}/endpoints",
            headers=admin_h,
            json={
                "resource_type": "http_endpoint",
                "code": "delete",
                "name": "删除工单",
                "method": "DELETE",
                "path_pattern": "/rest/api/3/issue/{key}",
                "expose_as_mcp": True,
                "mcp_tool_name": "jira_delete_issue",
            },
        )

        # B. Create Upstream Remote MCP platform + static auth + one-click sync
        mcp_pid = (
            await client.post(
                "/api/v1/admin/platforms",
                headers=admin_h,
                json={
                    "code": "hr_mcp",
                    "name": "HR MCP Server",
                    "protocol_type": "mcp",
                    "base_url": "https://mcp.upstream.local/mcp",
                    "mcp_transport": "streamable_http",
                },
            )
        ).json()["id"]
        await client.put(
            f"/api/v1/admin/platforms/{mcp_pid}/auth",
            headers=admin_h,
            json={
                "auth_type": "static",
                "location": "header",
                "param_name": "Authorization",
                "value": "upstream-mcp-secret",
                "value_prefix": "Bearer ",
            },
        )
        sync_resp = await client.post(
            f"/api/v1/admin/platforms/{mcp_pid}/sync-mcp-tools",
            headers=admin_h,
        )
        assert sync_resp.status_code == 200
        synced = {ep["code"]: ep for ep in sync_resp.json()}
        assert set(synced) == {"query_hr_staff", "terminate_staff"}
        hr_query_ep_id = synced["query_hr_staff"]["id"]

        # C. External role granting ONLY jira_search_issues + hr_mcp_query_hr_staff
        role_id = (
            await client.post(
                "/api/v1/admin/external-roles",
                headers=admin_h,
                json={"code": "ai_eng", "name": "研发 AI 助手角色"},
            )
        ).json()["id"]

        await client.post(
            f"/api/v1/admin/external-roles/{role_id}/policies",
            headers=admin_h,
            json={
                "platform_id": jira_pid,
                "endpoint_id": jira_search_ep,
                "name": "Jira 工单查询",
                "effect": "allow",
                "request_rules": {"enforce": {"args.project": "{{ user.attributes.project }}"}},
                "field_rules": {
                    "mode": "allowlist",
                    "fields": [
                        "issues[*].key",
                        "issues[*].summary",
                        "issues[*].reporter_email",
                    ],
                    "transforms": [
                        {"path": "issues[*].reporter_email", "action": "mask_email"}
                    ],
                },
            },
        )
        await client.post(
            f"/api/v1/admin/external-roles/{role_id}/policies",
            headers=admin_h,
            json={
                "platform_id": mcp_pid,
                "endpoint_id": hr_query_ep_id,
                "name": "HR 通讯录查询",
                "effect": "allow",
                "request_rules": {"enforce": {"args.dept": "{{ user.attributes.dept }}"}},
                "field_rules": {
                    "mode": "allowlist",
                    "fields": ["staff[*].name", "staff[*].mobile"],
                    "transforms": [{"path": "staff[*].mobile", "action": "mask_phone"}],
                },
            },
        )

        # D. Create user + External App delegation key to test MCP over app delegation too
        await client.post(
            "/api/v1/admin/users",
            headers=admin_h,
            json={
                "username": "dev1",
                "password": "DevPassword123!",
                "attributes": {"project": "ALPHA", "dept": "ENG"},
                "external_role_ids": [role_id],
            },
        )
        app_key = (
            await client.post(
                "/api/v1/admin/external-apps",
                headers=admin_h,
                json={"app_code": "ai_agent_hub", "name": "AI Agent Hub"},
            )
        ).json()["plain_key"]
        mcp_headers = {
            "Authorization": f"Bearer {app_key}",
            "X-FieldScope-User": "dev1",
        }

        # 1. MCP initialize
        init_resp = await client.post(
            "/mcp",
            headers=mcp_headers,
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        )
        assert init_resp.status_code == 200
        assert init_resp.json()["result"]["serverInfo"]["name"] == "FieldScope"

        # 2. MCP tools/list -> ONLY the 2 permitted tools visible (delete & terminate hidden!)
        list_resp = await client.post(
            "/mcp",
            headers=mcp_headers,
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        )
        tool_names = {t["name"] for t in list_resp.json()["result"]["tools"]}
        assert tool_names == {"jira_search_issues", "hr_mcp_query_hr_staff"}

        # 3. MCP tools/call on REST-to-MCP (attempting spoofed project=SECRET -> forced to ALPHA)
        call_jira = await client.post(
            "/mcp",
            headers=mcp_headers,
            json={
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "jira_search_issues", "arguments": {"project": "SECRET"}},
            },
        )
        jira_payload = json.loads(call_jira.json()["result"]["content"][0]["text"])
        assert jira_payload["issues"][0]["key"] == "ALPHA-1"
        assert jira_payload["issues"][0]["reporter_email"] == "l***d@corp.com"
        assert "secret_cost" not in jira_payload["issues"][0]

        # 4. MCP tools/call on Upstream MCP Proxy (salary pruned, mobile masked!)
        call_hr = await client.post(
            "/mcp",
            headers=mcp_headers,
            json={
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "hr_mcp_query_hr_staff", "arguments": {"dept": "EXEC"}},
            },
        )
        hr_payload = json.loads(call_hr.json()["result"]["content"][0]["text"])
        assert hr_payload["staff"][0]["name"] == "Alice"
        assert hr_payload["staff"][0]["mobile"] == "136****2222"
        assert "salary" not in hr_payload["staff"][0]

        # 5. Attempting forbidden tool -> JSON-RPC permission error (-32003) + audited!
        call_forbidden = await client.post(
            "/mcp",
            headers=mcp_headers,
            json={
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {"name": "hr_mcp_terminate_staff", "arguments": {}},
            },
        )
        assert call_forbidden.json()["error"]["code"] == -32003

        # 6. Audit logs confirm app_code + protocol="mcp"
        audits = (
            await client.get("/api/v1/admin/audit-logs?protocol=mcp", headers=admin_h)
        ).json()
        assert audits["total"] == 3
        assert all(item["app_code"] == "ai_agent_hub" for item in audits["items"])
