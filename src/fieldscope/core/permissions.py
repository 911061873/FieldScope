from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PermissionSpec:
    code: str
    name: str
    module: str
    description: str


# Platform internal permissions (control plane / admin UI capabilities)
BUILTIN_PERMISSIONS: tuple[PermissionSpec, ...] = (
    PermissionSpec("user:read", "查看用户", "iam", "查看平台用户列表、详情及角色绑定"),
    PermissionSpec("user:write", "管理用户", "iam", "创建、修改、启停用户及分配角色/管理用户 Key"),
    PermissionSpec("platform_role:read", "查看平台角色", "iam", "查看平台内部角色与权限列表"),
    PermissionSpec(
        "platform_role:write",
        "管理平台角色",
        "iam",
        "创建、修改、删除平台内部角色并配置权限",
    ),
    PermissionSpec("external_app:read", "查看外部应用", "iam", "查看代调用外部应用列表与详情"),
    PermissionSpec(
        "external_app:write",
        "管理外部应用",
        "iam",
        "创建、修改、轮换密钥、删除代调用外部应用",
    ),
    PermissionSpec(
        "platform:read",
        "查看三方平台",
        "platform",
        "查看三方平台、接口及 MCP 工具定义",
    ),
    PermissionSpec(
        "platform:write",
        "管理三方平台",
        "platform",
        "配置三方平台、认证与续期、同步接口/MCP 工具",
    ),
    PermissionSpec(
        "external_role:read",
        "查看外部数据角色",
        "policy",
        "查看外部数据角色及四层权限策略",
    ),
    PermissionSpec(
        "external_role:write",
        "管理外部数据角色",
        "policy",
        "创建、修改、删除外部数据角色及配置数据/字段策略",
    ),
    PermissionSpec("audit:read", "查看审计日志", "audit", "查询数据面调用审计日志与统计信息"),
)

ALL_PERMISSION_CODES: frozenset[str] = frozenset(p.code for p in BUILTIN_PERMISSIONS)


@dataclass(frozen=True)
class BuiltinRoleSpec:
    code: str
    name: str
    description: str
    permissions: tuple[str, ...]
    is_system: bool = True


BUILTIN_PLATFORM_ROLES: tuple[BuiltinRoleSpec, ...] = (
    BuiltinRoleSpec(
        code="super_admin",
        name="超级管理员",
        description="拥有平台内部全部管理能力",
        permissions=tuple(p.code for p in BUILTIN_PERMISSIONS),
    ),
    BuiltinRoleSpec(
        code="platform_admin",
        name="平台配置员",
        description="负责三方平台接入、外部应用、外部数据角色及策略配置",
        permissions=(
            "user:read",
            "external_app:read",
            "external_app:write",
            "platform:read",
            "platform:write",
            "external_role:read",
            "external_role:write",
            "audit:read",
        ),
    ),
    BuiltinRoleSpec(
        code="auditor",
        name="审计员",
        description="只读查看平台配置、角色策略和审计日志",
        permissions=(
            "user:read",
            "platform_role:read",
            "external_app:read",
            "platform:read",
            "external_role:read",
            "audit:read",
        ),
    ),
    BuiltinRoleSpec(
        code="member",
        name="普通成员",
        description="可登录管理台管理自己的个人 API Key 与个人信息",
        permissions=(),
    ),
)
