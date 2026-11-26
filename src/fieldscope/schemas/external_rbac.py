from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Structured 4-Layer External Policy Rules
# ---------------------------------------------------------------------------


class ValidationRule(BaseModel):
    expr: str = Field(min_length=1, description="Safe expression validated before upstream call")
    message: str = Field(default="Request parameter violates data scope policy")


class RequestRules(BaseModel):
    validate_rules: list[ValidationRule] = Field(
        default_factory=list,
        alias="validate",
        serialization_alias="validate",
    )
    enforce: dict[str, Any] = Field(
        default_factory=dict,
        description="Forced parameters injected before calling upstream (e.g. query.dept_id)",
    )

    model_config = {"populate_by_name": True}


class RowFilterRule(BaseModel):
    list_path: str = Field(
        default="",
        description="Dot-path to list inside JSON response (empty string for top-level list)",
    )
    expr: str = Field(
        min_length=1,
        description="Safe row-level predicate expression using row.* and user.*",
    )


FieldTransformAction = Literal[
    "mask_phone",
    "mask_email",
    "mask_middle",
    "redact",
    "hash",
]


class FieldTransform(BaseModel):
    path: str = Field(min_length=1, description="Field path (e.g. items[*].customer.phone)")
    action: FieldTransformAction


class FieldRules(BaseModel):
    mode: Literal["allowlist", "denylist"] = "allowlist"
    fields: list[str] = Field(default_factory=list)
    transforms: list[FieldTransform] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# External Data Roles & Policies CRUD Schemas
# ---------------------------------------------------------------------------


class ExternalRoleCreate(BaseModel):
    code: str = Field(min_length=2, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    name: str = Field(min_length=1, max_length=128)
    description: str = ""
    is_active: bool = True


class ExternalRoleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    description: str | None = None
    is_active: bool | None = None


class ExternalPolicyCreate(BaseModel):
    platform_id: int
    endpoint_id: int | None = None
    name: str = Field(default="", max_length=128)
    effect: Literal["allow", "deny"] = "allow"
    priority: int = Field(default=100, ge=0, le=10000)
    request_rules: RequestRules = Field(default_factory=RequestRules)
    row_filter: RowFilterRule | None = None
    field_rules: FieldRules | None = None
    is_active: bool = True


class ExternalPolicyUpdate(BaseModel):
    platform_id: int | None = None
    endpoint_id: int | None = None
    name: str | None = Field(default=None, max_length=128)
    effect: Literal["allow", "deny"] | None = None
    priority: int | None = Field(default=None, ge=0, le=10000)
    request_rules: RequestRules | None = None
    row_filter: RowFilterRule | None = None
    field_rules: FieldRules | None = None
    is_active: bool | None = None


class ExternalPolicyRead(BaseModel):
    id: int
    external_role_id: int
    platform_id: int
    endpoint_id: int | None
    name: str
    effect: str
    priority: int
    request_rules: dict[str, Any]
    row_filter: dict[str, Any] | None
    field_rules: dict[str, Any] | None
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ExternalRoleRead(BaseModel):
    id: int
    code: str
    name: str
    description: str
    is_active: bool
    policies: list[ExternalPolicyRead] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
