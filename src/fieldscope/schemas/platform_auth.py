from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field, model_validator

MASKED_SECRET_PLACEHOLDER = "********"

AuthLocation = Literal["header", "query"]


class BodyInvalidRule(BaseModel):
    """Detect expired/invalid token inside a JSON response body (e.g. HTTP 200 with code=40001)."""

    path: str = Field(min_length=1, description="JSONPath expression, e.g. $.code or errcode")
    equals: Any = None
    in_values: list[Any] | None = None

    @model_validator(mode="after")
    def _validate_matcher(self) -> BodyInvalidRule:
        if self.equals is None and not self.in_values:
            raise ValueError("BodyInvalidRule requires either 'equals' or non-empty 'in_values'")
        return self


class TokenInvalidRule(BaseModel):
    """Conditions that indicate the current token is invalid and should be refreshed + retried."""

    http_statuses: list[int] = Field(default_factory=lambda: [401])
    body_rules: list[BodyInvalidRule] = Field(default_factory=list)


class NoneAuthConfig(BaseModel):
    auth_type: Literal["none"] = "none"


class StaticAuthConfig(BaseModel):
    auth_type: Literal["static"] = "static"
    location: AuthLocation = "header"
    param_name: str = Field(default="Authorization", min_length=1, max_length=128)
    value: str = Field(min_length=1)
    value_prefix: str = Field(default="", description="Optional prefix such as 'Bearer '")


class OAuth2AuthConfig(BaseModel):
    auth_type: Literal["oauth2"] = "oauth2"
    grant_type: Literal["client_credentials", "authorization_code"] = "client_credentials"
    client_id: str = Field(min_length=1)
    client_secret: str = Field(min_length=1)
    token_url: str = Field(min_length=1)
    authorize_url: str | None = None
    redirect_uri: str | None = None
    scopes: list[str] = Field(default_factory=list)
    extra_token_params: dict[str, str] = Field(default_factory=dict)
    client_auth_method: Literal["body", "basic"] = "body"
    inject_location: AuthLocation = "header"
    inject_name: str = Field(default="Authorization", min_length=1, max_length=128)
    inject_prefix: str = Field(default="Bearer ")
    refresh_leeway_seconds: int = Field(default=60, ge=0, le=3600)
    default_ttl_seconds: int = Field(default=3600, ge=1, le=86400 * 30)
    invalid_rules: TokenInvalidRule = Field(default_factory=TokenInvalidRule)

    @model_validator(mode="after")
    def _validate_auth_code_fields(self) -> OAuth2AuthConfig:
        if self.grant_type == "authorization_code" and not self.authorize_url:
            raise ValueError("authorize_url is required when grant_type='authorization_code'")
        return self


class CustomHttpRequestSpec(BaseModel):
    method: Literal["GET", "POST", "PUT"] = "POST"
    url: str = Field(min_length=1)
    headers: dict[str, str] = Field(default_factory=dict)
    query: dict[str, Any] = Field(default_factory=dict)
    body_type: Literal["json", "form", "none"] = "json"
    body: dict[str, Any] = Field(default_factory=dict)


class CustomTokenResponseMapping(BaseModel):
    access_token_path: str = Field(default="$.access_token", min_length=1)
    refresh_token_path: str | None = None
    expires_in_path: str | None = "$.expires_in"
    expires_at_path: str | None = None
    fixed_ttl_seconds: int | None = Field(default=None, ge=1, le=86400 * 30)


class CustomHttpAuthConfig(BaseModel):
    auth_type: Literal["custom_http"] = "custom_http"
    token_request: CustomHttpRequestSpec
    refresh_request: CustomHttpRequestSpec | None = None
    secrets: dict[str, str] = Field(
        default_factory=dict,
        description="Encrypted key-value secrets referenced via {{ secret.xxx }} in request specs",
    )
    response_mapping: CustomTokenResponseMapping = Field(
        default_factory=CustomTokenResponseMapping
    )
    inject_location: AuthLocation = "header"
    inject_name: str = Field(default="Authorization", min_length=1, max_length=128)
    inject_prefix: str = Field(default="Bearer ")
    refresh_leeway_seconds: int = Field(default=60, ge=0, le=3600)
    default_ttl_seconds: int = Field(default=3600, ge=1, le=86400 * 30)
    invalid_rules: TokenInvalidRule = Field(default_factory=TokenInvalidRule)


PlatformAuthConfigPayload = Annotated[
    NoneAuthConfig | StaticAuthConfig | OAuth2AuthConfig | CustomHttpAuthConfig,
    Field(discriminator="auth_type"),
]


class PlatformAuthConfigRead(BaseModel):
    platform_id: int
    auth_type: str
    config: dict[str, Any]
    updated_at: datetime | None = None


class PlatformTokenStatusRead(BaseModel):
    platform_id: int
    auth_type: str
    has_access_token: bool
    has_refresh_token: bool
    token_preview: str | None = None
    token_type: str | None = None
    expires_at: datetime | None = None
    is_expired: bool = False
    last_refreshed_at: datetime | None = None
    last_error: str | None = None


class OAuthAuthorizeUrlResponse(BaseModel):
    authorize_url: str
    state: str


class OAuthCallbackRequest(BaseModel):
    code: str = Field(min_length=1)
    state: str = Field(min_length=1)
    redirect_uri: str | None = None


class PlatformAuthTestRequest(BaseModel):
    method: Literal["GET", "POST", "PUT", "DELETE", "PATCH"] = "GET"
    path: str = Field(default="", description="Path relative to platform base_url")
    query: dict[str, Any] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    body: Any = None


class PlatformAuthTestResponse(BaseModel):
    ok: bool
    upstream_status: int
    retried_after_refresh: bool
    latency_ms: int
    response_preview: Any = None
    error: str | None = None
