from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class PlatformCreate(BaseModel):
    code: str = Field(min_length=2, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    name: str = Field(min_length=1, max_length=128)
    description: str = ""
    protocol_type: Literal["api", "mcp"] = "api"
    base_url: str = Field(min_length=1, max_length=512)
    mcp_transport: Literal["streamable_http"] | None = None
    timeout_ms: int = Field(default=15000, ge=500, le=300000)
    extra_headers: dict[str, str] = Field(default_factory=dict)
    is_active: bool = True


class PlatformUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    description: str | None = None
    base_url: str | None = Field(default=None, min_length=1, max_length=512)
    mcp_transport: Literal["streamable_http"] | None = None
    timeout_ms: int | None = Field(default=None, ge=500, le=300000)
    extra_headers: dict[str, str] | None = None
    is_active: bool | None = None


class PlatformEndpointCreate(BaseModel):
    resource_type: Literal["http_endpoint", "mcp_tool"] = "http_endpoint"
    code: str = Field(min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_.:-]+$")
    name: str = Field(min_length=1, max_length=128)
    description: str = ""
    method: str | None = Field(default="GET", max_length=16)
    path_pattern: str | None = Field(default=None, max_length=512)
    expose_as_mcp: bool = True
    mcp_tool_name: str | None = Field(default=None, max_length=128)
    input_schema: dict[str, Any] = Field(default_factory=dict)
    output_schema: dict[str, Any] = Field(default_factory=dict)
    is_active: bool = True


class PlatformEndpointUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    description: str | None = None
    method: str | None = Field(default=None, max_length=16)
    path_pattern: str | None = Field(default=None, max_length=512)
    expose_as_mcp: bool | None = None
    mcp_tool_name: str | None = Field(default=None, max_length=128)
    input_schema: dict[str, Any] | None = None
    output_schema: dict[str, Any] | None = None
    is_active: bool | None = None


class PlatformEndpointRead(BaseModel):
    id: int
    platform_id: int
    resource_type: str
    code: str
    name: str
    description: str
    method: str | None
    path_pattern: str | None
    expose_as_mcp: bool
    mcp_tool_name: str | None
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class PlatformRead(BaseModel):
    id: int
    code: str
    name: str
    description: str
    protocol_type: str
    base_url: str
    mcp_transport: str | None
    timeout_ms: int
    extra_headers: dict[str, str]
    is_active: bool
    endpoints: list[PlatformEndpointRead] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
