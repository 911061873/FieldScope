from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest

from tests.conftest import login_and_get_headers


@pytest.mark.asyncio
async def test_bootstrap_admin_and_platform_rbac_isolation(client: httpx.AsyncClient) -> None:
    # Health check
    health = await client.get("/healthz")
    assert health.status_code == 200
    assert health.json() == {"status": "ok"}

    # Unauthenticated access to admin API must fail with 401
    unauth = await client.get("/api/v1/admin/users")
    assert unauth.status_code == 401

    # Login as bootstrap admin
    admin_headers = await login_and_get_headers(client)
    me = await client.get("/api/v1/admin/auth/me", headers=admin_headers)
    assert me.status_code == 200
    me_data = me.json()
    assert me_data["username"] == "admin"
    assert me_data["is_superuser"] is True
    assert "user:write" in me_data["platform_permissions"]
    assert "external_role:write" in me_data["platform_permissions"]

    # Built-in platform permissions & system roles exist
    perms_resp = await client.get("/api/v1/admin/platform-permissions", headers=admin_headers)
    assert perms_resp.status_code == 200
    assert len(perms_resp.json()) >= 11

    roles_resp = await client.get("/api/v1/admin/platform-roles", headers=admin_headers)
    assert roles_resp.status_code == 200
    roles_by_code = {r["code"]: r for r in roles_resp.json()}
    assert {"super_admin", "platform_admin", "auditor", "member"} <= set(roles_by_code)

    # Deleting system role is rejected
    del_sys = await client.delete(
        f"/api/v1/admin/platform-roles/{roles_by_code['super_admin']['id']}",
        headers=admin_headers,
    )
    assert del_sys.status_code == 400

    # Create a custom platform internal role (read-only on platforms only)
    custom_role_resp = await client.post(
        "/api/v1/admin/platform-roles",
        headers=admin_headers,
        json={
            "code": "platform_viewer",
            "name": "三方平台只读查看员",
            "description": "仅允许查看三方平台",
            "permission_codes": ["platform:read"],
        },
    )
    assert custom_role_resp.status_code == 201
    viewer_role_id = custom_role_resp.json()["id"]

    # Create a regular user with ONLY platform_viewer internal role
    user_resp = await client.post(
        "/api/v1/admin/users",
        headers=admin_headers,
        json={
            "username": "alice",
            "password": "AlicePassword123!",
            "display_name": "Alice",
            "department": "Engineering",
            "attributes": {"dept_id": "ENG-01", "project": "PROJ-A"},
            "platform_role_ids": [viewer_role_id],
        },
    )
    assert user_resp.status_code == 201

    # Alice logs in: can read platforms, CANNOT list users or write platforms
    alice_headers = await login_and_get_headers(client, "alice", "AlicePassword123!")
    assert (await client.get("/api/v1/admin/platforms", headers=alice_headers)).status_code == 200
    assert (await client.get("/api/v1/admin/users", headers=alice_headers)).status_code == 403
    create_plat_denied = await client.post(
        "/api/v1/admin/platforms",
        headers=alice_headers,
        json={
            "code": "jira",
            "name": "Jira",
            "protocol_type": "api",
            "base_url": "https://jira.example.com",
        },
    )
    assert create_plat_denied.status_code == 403


@pytest.mark.asyncio
async def test_external_role_4layer_policies_and_dual_mode_data_plane_auth(
    client: httpx.AsyncClient,
) -> None:
    admin_headers = await login_and_get_headers(client)

    # 1. Create a third-party API platform & endpoint
    plat_resp = await client.post(
        "/api/v1/admin/platforms",
        headers=admin_headers,
        json={
            "code": "crm",
            "name": "Enterprise CRM",
            "protocol_type": "api",
            "base_url": "https://crm.internal.example.com",
        },
    )
    assert plat_resp.status_code == 201
    platform_id = plat_resp.json()["id"]

    ep_resp = await client.post(
        f"/api/v1/admin/platforms/{platform_id}/endpoints",
        headers=admin_headers,
        json={
            "resource_type": "http_endpoint",
            "code": "list_customers",
            "name": "查询客户列表",
            "method": "GET",
            "path_pattern": "/api/v1/customers",
            "expose_as_mcp": True,
            "mcp_tool_name": "crm_list_customers",
            "input_schema": {
                "type": "object",
                "properties": {"dept_id": {"type": "string"}, "limit": {"type": "integer"}},
            },
        },
    )
    assert ep_resp.status_code == 201
    endpoint_id = ep_resp.json()["id"]

    # 2. Create an External Data Role & attach a 4-layer policy
    ext_role_resp = await client.post(
        "/api/v1/admin/external-roles",
        headers=admin_headers,
        json={
            "code": "sales_east",
            "name": "华东销售数据角色",
            "description": "仅允许查询华东区客户并脱敏手机号",
        },
    )
    assert ext_role_resp.status_code == 201
    ext_role_id = ext_role_resp.json()["id"]

    pol_resp = await client.post(
        f"/api/v1/admin/external-roles/{ext_role_id}/policies",
        headers=admin_headers,
        json={
            "platform_id": platform_id,
            "endpoint_id": endpoint_id,
            "name": "华东客户列表只读策略",
            "effect": "allow",
            "priority": 100,
            "request_rules": {
                "validate": [{"expr": "query.limit <= 50", "message": "最多返回 50 条"}],
                "enforce": {"query.region": "{{ user.attributes.region }}"},
            },
            "row_filter": {
                "list_path": "data.items",
                "expr": "row.owner == user.username",
            },
            "field_rules": {
                "mode": "allowlist",
                "fields": ["data.items[*].id", "data.items[*].name", "data.items[*].phone"],
                "transforms": [{"path": "data.items[*].phone", "action": "mask_phone"}],
            },
        },
    )
    assert pol_resp.status_code == 201
    policy_data = pol_resp.json()
    assert policy_data["request_rules"]["enforce"]["query.region"] == "{{ user.attributes.region }}"
    assert policy_data["row_filter"]["list_path"] == "data.items"
    assert policy_data["field_rules"]["transforms"][0]["action"] == "mask_phone"

    # 3. Create business user Bob with ZERO platform admin permissions, only ExternalRole
    bob_resp = await client.post(
        "/api/v1/admin/users",
        headers=admin_headers,
        json={
            "username": "bob",
            "password": "BobPassword123!",
            "display_name": "Bob Sales",
            "department": "Sales",
            "attributes": {"region": "east"},
            "platform_role_ids": [],
            "external_role_ids": [ext_role_id],
        },
    )
    assert bob_resp.status_code == 201
    bob_id = bob_resp.json()["id"]
    assert bob_resp.json()["platform_roles"] == []
    assert [r["code"] for r in bob_resp.json()["external_roles"]] == ["sales_east"]

    # 4. Mode 1: Bob self-creates personal API Key -> calls data-plane whoami
    bob_jwt_headers = await login_and_get_headers(client, "bob", "BobPassword123!")
    key_resp = await client.post(
        "/api/v1/admin/auth/me/api-keys",
        headers=bob_jwt_headers,
        json={"name": "bob-mcp-key"},
    )
    assert key_resp.status_code == 201
    bob_plain_key = key_resp.json()["plain_key"]
    bob_key_id = key_resp.json()["id"]
    assert bob_plain_key.startswith("fs_usr_")

    whoami_usr = await client.get(
        "/api/v1/data-plane/whoami",
        headers={"Authorization": f"Bearer {bob_plain_key}"},
    )
    assert whoami_usr.status_code == 200
    assert whoami_usr.json()["auth_mode"] == "user_api_key"
    assert whoami_usr.json()["username"] == "bob"
    assert whoami_usr.json()["attributes"] == {"region": "east"}
    assert [r["code"] for r in whoami_usr.json()["external_roles"]] == ["sales_east"]

    # Expired personal key is rejected
    expired_resp = await client.post(
        f"/api/v1/admin/users/{bob_id}/api-keys",
        headers=admin_headers,
        json={
            "name": "expired-key",
            "expires_at": (datetime.now(UTC) - timedelta(minutes=5)).isoformat(),
        },
    )
    assert expired_resp.status_code == 201
    exp_whoami = await client.get(
        "/api/v1/data-plane/whoami",
        headers={"Authorization": f"Bearer {expired_resp.json()['plain_key']}"},
    )
    assert exp_whoami.status_code == 401

    # Revoking Bob's personal key immediately invalidates it
    assert (
        await client.delete(
            f"/api/v1/admin/auth/me/api-keys/{bob_key_id}",
            headers=bob_jwt_headers,
        )
    ).status_code == 200
    assert (
        await client.get(
            "/api/v1/data-plane/whoami",
            headers={"Authorization": f"Bearer {bob_plain_key}"},
        )
    ).status_code == 401

    # 5. Mode 2: External App delegated authentication (fs_app_* + X-FieldScope-User)
    app_resp = await client.post(
        "/api/v1/admin/external-apps",
        headers=admin_headers,
        json={
            "app_code": "oa_portal",
            "name": "企业 OA 门户",
            "user_identity_header": "X-FieldScope-User",
        },
    )
    assert app_resp.status_code == 201
    app_id = app_resp.json()["id"]
    app_plain_key = app_resp.json()["plain_key"]
    assert app_plain_key.startswith("fs_app_")

    # Missing delegated user header -> 400
    missing_hdr = await client.get(
        "/api/v1/data-plane/whoami",
        headers={"Authorization": f"Bearer {app_plain_key}"},
    )
    assert missing_hdr.status_code == 400

    # Valid delegated call -> resolves Bob with his external roles
    delegated = await client.get(
        "/api/v1/data-plane/whoami",
        headers={
            "Authorization": f"Bearer {app_plain_key}",
            "X-FieldScope-User": "bob",
        },
    )
    assert delegated.status_code == 200
    assert delegated.json()["auth_mode"] == "external_app_delegation"
    assert delegated.json()["username"] == "bob"
    assert delegated.json()["app_code"] == "oa_portal"
    assert [r["code"] for r in delegated.json()["external_roles"]] == ["sales_east"]

    # Rotating app key invalidates old key and activates new key
    rot_resp = await client.post(
        f"/api/v1/admin/external-apps/{app_id}/rotate-key",
        headers=admin_headers,
    )
    assert rot_resp.status_code == 200
    new_app_key = rot_resp.json()["plain_key"]
    assert new_app_key != app_plain_key

    assert (
        await client.get(
            "/api/v1/data-plane/whoami",
            headers={"Authorization": f"Bearer {app_plain_key}", "X-FieldScope-User": "bob"},
        )
    ).status_code == 401
    assert (
        await client.get(
            "/api/v1/data-plane/whoami",
            headers={"Authorization": f"Bearer {new_app_key}", "X-FieldScope-User": "bob"},
        )
    ).status_code == 200

    # Disabling Bob blocks delegated calls as Bob
    assert (
        await client.patch(
            f"/api/v1/admin/users/{bob_id}",
            headers=admin_headers,
            json={"is_active": False},
        )
    ).status_code == 200
    assert (
        await client.get(
            "/api/v1/data-plane/whoami",
            headers={"Authorization": f"Bearer {new_app_key}", "X-FieldScope-User": "bob"},
        )
    ).status_code == 403
