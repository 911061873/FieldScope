from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from fieldscope.schemas.common import RoleBrief

# ---------------------------------------------------------------------------
# Platform Internal Permissions & Roles
# ---------------------------------------------------------------------------


class PlatformPermissionRead(BaseModel):
    id: int
    code: str
    name: str
    module: str
    description: str

    model_config = {"from_attributes": True}


class PlatformRoleCreate(BaseModel):
    code: str = Field(min_length=2, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    name: str = Field(min_length=1, max_length=128)
    description: str = ""
    permission_codes: list[str] = Field(default_factory=list)


class PlatformRoleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    description: str | None = None
    permission_codes: list[str] | None = None


class PlatformRoleRead(BaseModel):
    id: int
    code: str
    name: str
    description: str
    is_system: bool
    permissions: list[PlatformPermissionRead]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Users & Personal API Keys
# ---------------------------------------------------------------------------


class UserCreate(BaseModel):
    username: str = Field(min_length=2, max_length=64, pattern=r"^[a-zA-Z0-9._-]+$")
    password: str = Field(min_length=6, max_length=128)
    display_name: str = ""
    email: str | None = None
    department: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    is_active: bool = True
    is_superuser: bool = False
    platform_role_ids: list[int] = Field(default_factory=list)
    external_role_ids: list[int] = Field(default_factory=list)


class UserUpdate(BaseModel):
    password: str | None = Field(default=None, min_length=6, max_length=128)
    display_name: str | None = None
    email: str | None = None
    department: str | None = None
    attributes: dict[str, Any] | None = None
    is_active: bool | None = None
    is_superuser: bool | None = None


class UserRoleAssignRequest(BaseModel):
    role_ids: list[int] = Field(default_factory=list)


class UserRead(BaseModel):
    id: int
    username: str
    display_name: str
    email: str | None
    department: str | None
    attributes: dict[str, Any]
    is_active: bool
    is_superuser: bool
    platform_roles: list[RoleBrief]
    external_roles: list[RoleBrief]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class UserApiKeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    expires_at: datetime | None = None


class UserApiKeyRead(BaseModel):
    id: int
    user_id: int
    name: str
    key_prefix: str
    expires_at: datetime | None
    last_used_at: datetime | None
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class UserApiKeyCreated(UserApiKeyRead):
    """Returned once upon creation; plain_key is never retrievable again."""

    plain_key: str


# ---------------------------------------------------------------------------
# External Applications (Delegated Callers)
# ---------------------------------------------------------------------------


class ExternalAppCreate(BaseModel):
    app_code: str = Field(min_length=2, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    name: str = Field(min_length=1, max_length=128)
    description: str = ""
    user_identity_header: str = Field(default="X-FieldScope-User", min_length=1, max_length=64)
    is_active: bool = True


class ExternalAppUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    description: str | None = None
    user_identity_header: str | None = Field(default=None, min_length=1, max_length=64)
    is_active: bool | None = None


class ExternalAppRead(BaseModel):
    id: int
    app_code: str
    name: str
    description: str
    key_prefix: str
    user_identity_header: str
    last_used_at: datetime | None
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ExternalAppCreated(ExternalAppRead):
    """Returned once on creation or key rotation; plain_key is never retrievable again."""

    plain_key: str
