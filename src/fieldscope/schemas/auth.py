from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from fieldscope.schemas.common import RoleBrief


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime


class CurrentUserResponse(BaseModel):
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
    platform_permissions: list[str]


class DataPlanePrincipalResponse(BaseModel):
    auth_mode: str  # "user_api_key" | "external_app_delegation"
    user_id: int
    username: str
    display_name: str
    department: str | None
    attributes: dict[str, Any]
    external_roles: list[RoleBrief]
    app_id: int | None = None
    app_code: str | None = None
