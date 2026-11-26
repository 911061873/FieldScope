from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from fieldscope.db.base import Base, TimestampMixin, UTCDateTime

# ---------------------------------------------------------------------------
# Association tables (Dual-Track RBAC: Platform Internal vs External Data)
# ---------------------------------------------------------------------------

user_platform_roles = Table(
    "user_platform_roles",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column(
        "platform_role_id",
        Integer,
        ForeignKey("platform_roles.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)

platform_role_permissions = Table(
    "platform_role_permissions",
    Base.metadata,
    Column(
        "platform_role_id",
        Integer,
        ForeignKey("platform_roles.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "permission_id",
        Integer,
        ForeignKey("platform_permissions.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)

user_external_roles = Table(
    "user_external_roles",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column(
        "external_role_id",
        Integer,
        ForeignKey("external_roles.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


# ---------------------------------------------------------------------------
# IAM: Users, Personal API Keys, External Apps, Platform Internal Roles
# ---------------------------------------------------------------------------


class User(TimestampMixin, Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    department: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Arbitrary user attributes used in data-scope expressions/templates, e.g. {"dept_id": "D01"}
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_superuser: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    api_keys: Mapped[list[UserApiKey]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )
    platform_roles: Mapped[list[PlatformRole]] = relationship(
        secondary=user_platform_roles,
        back_populates="users",
    )
    external_roles: Mapped[list[ExternalRole]] = relationship(
        secondary=user_external_roles,
        back_populates="users",
    )


class UserApiKey(TimestampMixin, Base):
    """Personal API key for direct AI/MCP or HTTP data-plane calls as a specific user."""

    __tablename__ = "user_api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(32), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    user: Mapped[User] = relationship(back_populates="api_keys")


class ExternalApp(TimestampMixin, Base):
    """Trusted external app credential for delegated user calls (App Key + User Header)."""

    __tablename__ = "external_apps"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    app_code: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(32), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    user_identity_header: Mapped[str] = mapped_column(
        String(64),
        default="X-FieldScope-User",
        nullable=False,
    )
    # Optional delegation scope: when non-empty, only matching users/external-roles may be delegated
    allowed_user_ids: Mapped[list[int]] = mapped_column(JSON, default=list, nullable=False)
    allowed_external_role_ids: Mapped[list[int]] = mapped_column(
        JSON, default=list, nullable=False
    )
    last_used_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class PlatformPermission(Base):
    """Control-plane internal permission code (menus & admin API capabilities)."""

    __tablename__ = "platform_permissions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    code: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    module: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)

    roles: Mapped[list[PlatformRole]] = relationship(
        secondary=platform_role_permissions,
        back_populates="permissions",
    )


class PlatformRole(TimestampMixin, Base):
    """Role restricting what a user can do INSIDE the FieldScope management platform."""

    __tablename__ = "platform_roles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    code: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    is_system: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    permissions: Mapped[list[PlatformPermission]] = relationship(
        secondary=platform_role_permissions,
        back_populates="roles",
    )
    users: Mapped[list[User]] = relationship(
        secondary=user_platform_roles,
        back_populates="platform_roles",
    )


# ---------------------------------------------------------------------------
# Third-Party Platforms, Credentials, Token States & Endpoints/MCP Tools
# ---------------------------------------------------------------------------


class Platform(TimestampMixin, Base):
    """Registered third-party platform supporting API or remote MCP integration."""

    __tablename__ = "platforms"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    code: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    # "api" | "mcp"
    protocol_type: Mapped[str] = mapped_column(String(16), default="api", nullable=False)
    base_url: Mapped[str] = mapped_column(String(512), nullable=False)
    # For MCP platforms: "streamable_http" | "sse"
    mcp_transport: Mapped[str | None] = mapped_column(String(32), nullable=True)
    timeout_ms: Mapped[int] = mapped_column(Integer, default=15000, nullable=False)
    extra_headers: Mapped[dict[str, str]] = mapped_column(JSON, default=dict, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    auth_config: Mapped[PlatformAuthConfig | None] = relationship(
        back_populates="platform",
        uselist=False,
        cascade="all, delete-orphan",
    )
    token_state: Mapped[PlatformTokenState | None] = relationship(
        back_populates="platform",
        uselist=False,
        cascade="all, delete-orphan",
    )
    endpoints: Mapped[list[PlatformEndpoint]] = relationship(
        back_populates="platform",
        cascade="all, delete-orphan",
    )
    policies: Mapped[list[ExternalPolicy]] = relationship(
        back_populates="platform",
        cascade="all, delete-orphan",
    )


class PlatformAuthConfig(TimestampMixin, Base):
    """Encrypted platform-level authentication configuration (static / oauth2 / custom_http)."""

    __tablename__ = "platform_auth_configs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    platform_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("platforms.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )
    # "none" | "static" | "oauth2" | "custom_http"
    auth_type: Mapped[str] = mapped_column(String(32), default="none", nullable=False)
    # AES-256-GCM encrypted JSON blob storing auth details & secrets
    config_encrypted: Mapped[str] = mapped_column(Text, default="", nullable=False)

    platform: Mapped[Platform] = relationship(back_populates="auth_config")


class PlatformTokenState(TimestampMixin, Base):
    """Persistent encrypted dynamic token cache so OAuth refresh_token survives restarts."""

    __tablename__ = "platform_token_states"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    platform_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("platforms.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )
    access_token_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    refresh_token_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    token_type: Mapped[str] = mapped_column(String(32), default="Bearer", nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    last_refreshed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    platform: Mapped[Platform] = relationship(back_populates="token_state")


class PlatformEndpoint(TimestampMixin, Base):
    """Registered API endpoint or synchronized upstream MCP tool belonging to a platform."""

    __tablename__ = "platform_endpoints"
    __table_args__ = (
        UniqueConstraint("platform_id", "code", name="uq_platform_endpoint_code"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    platform_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("platforms.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    # "http_endpoint" | "mcp_tool"
    resource_type: Mapped[str] = mapped_column(String(32), default="http_endpoint", nullable=False)
    code: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    # HTTP endpoint fields
    method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    path_pattern: Mapped[str | None] = mapped_column(String(512), nullable=True)
    expose_as_mcp: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    mcp_tool_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Schema definitions (used for MCP tool inputSchema & UI field permission picker)
    input_schema: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    output_schema: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    platform: Mapped[Platform] = relationship(back_populates="endpoints")
    policies: Mapped[list[ExternalPolicy]] = relationship(
        back_populates="endpoint",
        cascade="all, delete-orphan",
    )


# ---------------------------------------------------------------------------
# External Data Roles & 4-Layer Granular Policies
# ---------------------------------------------------------------------------


class ExternalRole(TimestampMixin, Base):
    """Role restricting which external platforms, endpoints, data scopes & fields a user can use."""

    __tablename__ = "external_roles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    code: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    users: Mapped[list[User]] = relationship(
        secondary=user_external_roles,
        back_populates="external_roles",
    )
    policies: Mapped[list[ExternalPolicy]] = relationship(
        back_populates="external_role",
        cascade="all, delete-orphan",
    )


class ExternalPolicy(TimestampMixin, Base):
    """4-layer external access policy: Platform -> Endpoint/Tool -> Data Scope -> Field Scope."""

    __tablename__ = "external_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    external_role_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("external_roles.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    platform_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("platforms.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    # Null endpoint_id means platform-wide wildcard policy (all endpoints of this platform)
    endpoint_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("platform_endpoints.id", ondelete="CASCADE"),
        index=True,
        nullable=True,
    )
    name: Mapped[str] = mapped_column(String(128), default="", nullable=False)
    # "allow" | "deny"
    effect: Mapped[str] = mapped_column(String(16), default="allow", nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    # Pre-request validation & forced parameter injection rules
    request_rules: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    # Post-response row-level filter rules
    row_filter: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    # Response field pruning & masking rules
    field_rules: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    external_role: Mapped[ExternalRole] = relationship(back_populates="policies")
    platform: Mapped[Platform] = relationship(back_populates="policies")
    endpoint: Mapped[PlatformEndpoint | None] = relationship(back_populates="policies")


# ---------------------------------------------------------------------------
# Audit Trail (Metadata only, no raw sensitive response bodies)
# ---------------------------------------------------------------------------


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    trace_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    user_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )
    username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    app_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("external_apps.id", ondelete="SET NULL"),
        index=True,
        nullable=True,
    )
    app_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # "http" | "mcp"
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)
    platform_code: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    endpoint_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # "allow" | "deny" | "error"
    decision: Mapped[str] = mapped_column(String(16), index=True, nullable=False)
    matched_policy_ids: Mapped[list[int]] = mapped_column(JSON, default=list, nullable=False)
    enforced_params: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    rows_before: Mapped[int | None] = mapped_column(Integer, nullable=True)
    rows_after: Mapped[int | None] = mapped_column(Integer, nullable=True)
    pruned_fields: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    transformed_fields: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    upstream_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), index=True, nullable=False)
