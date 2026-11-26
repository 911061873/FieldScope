from __future__ import annotations

import base64
import re
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt
from pydantic import TypeAdapter
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fieldscope.auth_engine.cache import CachedToken, InMemoryTokenCache, TokenCacheBackend
from fieldscope.auth_engine.jsonpath import extract_json_path, extract_json_path_strict
from fieldscope.core.crypto import SecretCipher
from fieldscope.db.base import utc_now
from fieldscope.db.models import Platform, PlatformAuthConfig, PlatformTokenState
from fieldscope.schemas.platform_auth import (
    MASKED_SECRET_PLACEHOLDER,
    CustomHttpAuthConfig,
    CustomHttpRequestSpec,
    NoneAuthConfig,
    OAuth2AuthConfig,
    PlatformAuthConfigPayload,
    StaticAuthConfig,
    TokenInvalidRule,
)

_AUTH_CONFIG_ADAPTER: TypeAdapter[PlatformAuthConfigPayload] = TypeAdapter(
    PlatformAuthConfigPayload
)
_TEMPLATE_VAR_RE = re.compile(r"\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}")


class AuthEngineError(RuntimeError):
    """Raised when acquiring, refreshing, or applying platform credentials fails."""


class OAuthAuthorizationRequiredError(AuthEngineError):
    """Raised when an authorization_code OAuth platform has not yet been authorized by an admin."""


@dataclass(frozen=True)
class AuthInjection:
    """HTTP headers and query parameters to attach to an outbound upstream request."""

    headers: dict[str, str] = field(default_factory=dict)
    query_params: dict[str, str] = field(default_factory=dict)
    raw_token: str | None = None
    is_dynamic: bool = False


def parse_auth_config(raw: dict[str, Any] | None) -> PlatformAuthConfigPayload:
    if not raw:
        return NoneAuthConfig()
    return _AUTH_CONFIG_ADAPTER.validate_python(raw)


def mask_auth_config(config: PlatformAuthConfigPayload) -> dict[str, Any]:
    """Return a JSON-safe config dict with secret fields masked for API responses."""
    data = config.model_dump(mode="json")
    if isinstance(config, StaticAuthConfig):
        if data.get("value"):
            data["value"] = MASKED_SECRET_PLACEHOLDER
    elif isinstance(config, OAuth2AuthConfig):
        if data.get("client_secret"):
            data["client_secret"] = MASKED_SECRET_PLACEHOLDER
    elif isinstance(config, CustomHttpAuthConfig):
        secrets_map = data.get("secrets") or {}
        data["secrets"] = {k: MASKED_SECRET_PLACEHOLDER for k in secrets_map}
    return data


def merge_preserved_secrets(
    incoming: PlatformAuthConfigPayload,
    existing: PlatformAuthConfigPayload | None,
) -> PlatformAuthConfigPayload:
    """Preserve previously stored secrets when an update sends the masked placeholder."""
    if existing is None or incoming.auth_type != existing.auth_type:
        return incoming

    if isinstance(incoming, StaticAuthConfig) and isinstance(existing, StaticAuthConfig):
        if incoming.value == MASKED_SECRET_PLACEHOLDER:
            return incoming.model_copy(update={"value": existing.value})

    elif isinstance(incoming, OAuth2AuthConfig) and isinstance(existing, OAuth2AuthConfig):
        if incoming.client_secret == MASKED_SECRET_PLACEHOLDER:
            return incoming.model_copy(update={"client_secret": existing.client_secret})

    elif isinstance(incoming, CustomHttpAuthConfig) and isinstance(existing, CustomHttpAuthConfig):
        merged_secrets: dict[str, str] = {}
        for k, v in incoming.secrets.items():
            if v == MASKED_SECRET_PLACEHOLDER and k in existing.secrets:
                merged_secrets[k] = existing.secrets[k]
            else:
                merged_secrets[k] = v
        return incoming.model_copy(update={"secrets": merged_secrets})

    return incoming


def mask_token_preview(token: str | None) -> str | None:
    if not token:
        return None
    if len(token) <= 8:
        return "***"
    return f"{token[:4]}***{token[-4:]}"


def _resolve_context_path(context: dict[str, Any], dotted_path: str) -> Any:
    current: Any = context
    for part in dotted_path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            raise AuthEngineError(f"Template variable '{dotted_path}' is not defined")
    return current


def _render_template(value: Any, context: dict[str, Any]) -> Any:
    if isinstance(value, str):
        full_match = _TEMPLATE_VAR_RE.fullmatch(value.strip())
        if full_match and value.strip() == value:
            return _resolve_context_path(context, full_match.group(1))

        def _replacer(match: re.Match[str]) -> str:
            resolved = _resolve_context_path(context, match.group(1))
            return "" if resolved is None else str(resolved)

        return _TEMPLATE_VAR_RE.sub(_replacer, value)

    if isinstance(value, dict):
        return {k: _render_template(v, context) for k, v in value.items()}
    if isinstance(value, list):
        return [_render_template(item, context) for item in value]
    return value


def _parse_expires_at(
    *,
    now: datetime,
    expires_in_raw: Any = None,
    expires_at_raw: Any = None,
    fixed_ttl_seconds: int | None = None,
    default_ttl_seconds: int = 3600,
) -> datetime:
    if expires_at_raw is not None:
        if isinstance(expires_at_raw, (int, float)):
            # Support both epoch seconds and milliseconds
            ts = float(expires_at_raw)
            if ts > 1e12:
                ts /= 1000.0
            return datetime.fromtimestamp(ts, tz=UTC)
        if isinstance(expires_at_raw, str):
            raw_str = expires_at_raw.strip()
            if raw_str.isdigit():
                ts = float(raw_str)
                if ts > 1e12:
                    ts /= 1000.0
                return datetime.fromtimestamp(ts, tz=UTC)
            parsed = datetime.fromisoformat(raw_str.replace("Z", "+00:00"))
            return parsed.astimezone(UTC) if parsed.tzinfo else parsed.replace(tzinfo=UTC)

    if expires_in_raw is not None:
        try:
            seconds = float(expires_in_raw)
            if seconds > 0:
                return now + timedelta(seconds=seconds)
        except (TypeError, ValueError):
            pass

    ttl = fixed_ttl_seconds if fixed_ttl_seconds is not None else default_ttl_seconds
    return now + timedelta(seconds=ttl)


def is_token_invalid_response(
    invalid_rules: TokenInvalidRule,
    status_code: int,
    body_json: Any = None,
) -> bool:
    """Return True if an upstream response signals an expired or rejected token."""
    if status_code in invalid_rules.http_statuses:
        return True
    if body_json is not None and invalid_rules.body_rules:
        for rule in invalid_rules.body_rules:
            found, actual = extract_json_path_strict(body_json, rule.path)
            if not found:
                continue
            if rule.equals is not None and actual == rule.equals:
                return True
            if rule.in_values and actual in rule.in_values:
                return True
    return False


class AuthEngine:
    """Manages platform-level credentials, dynamic token acquisition, renewal, and replay."""

    def __init__(
        self,
        cipher: SecretCipher,
        cache: TokenCacheBackend | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        self._cipher = cipher
        self._cache: TokenCacheBackend = cache or InMemoryTokenCache()
        self._external_http_client = http_client
        # Single-use OAuth state nonce registry: nonce -> expiration unix timestamp
        self._oauth_state_nonces: dict[str, float] = {}

    def _auth_aad(self, platform_id: int) -> str:
        return f"platform:{platform_id}:auth"

    def _token_aad(self, platform_id: int) -> str:
        return f"platform:{platform_id}:token"

    def _cache_key(self, platform_id: int) -> str:
        return f"platform:{platform_id}:token"

    def get_token_preview(self, platform_id: int, state: PlatformTokenState) -> str | None:
        """Safely decrypt and mask a stored access token for admin status views."""
        if not state.access_token_encrypted:
            return None
        try:
            decrypted = self._cipher.decrypt_str(
                state.access_token_encrypted,
                aad=self._token_aad(platform_id),
            )
            return mask_token_preview(decrypted)
        except Exception:
            return "***"

    async def load_auth_config(
        self,
        db: AsyncSession,
        platform_id: int,
    ) -> tuple[PlatformAuthConfigPayload, PlatformAuthConfig | None]:
        row = await db.scalar(
            select(PlatformAuthConfig).where(PlatformAuthConfig.platform_id == platform_id)
        )
        if row is None or row.auth_type == "none" or not row.config_encrypted:
            return NoneAuthConfig(), row
        decrypted = self._cipher.decrypt_json(row.config_encrypted, aad=self._auth_aad(platform_id))
        return parse_auth_config(decrypted), row

    async def save_auth_config(
        self,
        db: AsyncSession,
        platform_id: int,
        incoming: PlatformAuthConfigPayload,
    ) -> tuple[PlatformAuthConfigPayload, PlatformAuthConfig]:
        existing_cfg, existing_row = await self.load_auth_config(db, platform_id)
        merged = merge_preserved_secrets(
            incoming,
            existing_cfg if existing_row is not None else None,
        )
        encrypted = (
            ""
            if isinstance(merged, NoneAuthConfig)
            else self._cipher.encrypt_json(
                merged.model_dump(mode="json"),
                aad=self._auth_aad(platform_id),
            )
        )

        if existing_row is None:
            row = PlatformAuthConfig(
                platform_id=platform_id,
                auth_type=merged.auth_type,
                config_encrypted=encrypted,
            )
            db.add(row)
        else:
            existing_row.auth_type = merged.auth_type
            existing_row.config_encrypted = encrypted
            row = existing_row

        # Clear cached dynamic token whenever auth configuration changes
        await self.invalidate_token(db, platform_id, clear_refresh_token=True)
        await db.commit()
        await db.refresh(row)
        return merged, row

    async def invalidate_token(
        self,
        db: AsyncSession,
        platform_id: int,
        *,
        clear_refresh_token: bool = False,
    ) -> None:
        await self._cache.delete(self._cache_key(platform_id))
        state = await db.scalar(
            select(PlatformTokenState).where(PlatformTokenState.platform_id == platform_id)
        )
        if state is not None:
            state.access_token_encrypted = None
            state.expires_at = None
            if clear_refresh_token:
                state.refresh_token_encrypted = None
                state.last_error = None

    async def _load_db_token(
        self,
        db: AsyncSession,
        platform_id: int,
    ) -> CachedToken | None:
        state = await db.scalar(
            select(PlatformTokenState).where(PlatformTokenState.platform_id == platform_id)
        )
        if state is None or (
            not state.access_token_encrypted and not state.refresh_token_encrypted
        ):
            return None

        aad = self._token_aad(platform_id)
        access_token = (
            self._cipher.decrypt_str(state.access_token_encrypted, aad=aad)
            if state.access_token_encrypted
            else ""
        )
        refresh_token = (
            self._cipher.decrypt_str(state.refresh_token_encrypted, aad=aad)
            if state.refresh_token_encrypted
            else None
        )
        return CachedToken(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type=state.token_type,
            expires_at=state.expires_at,
        )

    async def _load_cached_or_db_token(
        self,
        db: AsyncSession,
        platform_id: int,
    ) -> CachedToken | None:
        cached = await self._cache.get(self._cache_key(platform_id))
        if cached is not None:
            return cached

        token = await self._load_db_token(db, platform_id)
        if token is None or not token.access_token:
            return None
        await self._cache.set(self._cache_key(platform_id), token)
        return token

    async def _load_db_refresh_token(self, db: AsyncSession, platform_id: int) -> str | None:
        state = await db.scalar(
            select(PlatformTokenState).where(PlatformTokenState.platform_id == platform_id)
        )
        if state is None or not state.refresh_token_encrypted:
            return None
        return self._cipher.decrypt_str(
            state.refresh_token_encrypted,
            aad=self._token_aad(platform_id),
        )

    async def _persist_token(
        self,
        db: AsyncSession,
        platform_id: int,
        token: CachedToken,
    ) -> PlatformTokenState:
        now = utc_now()
        aad = self._token_aad(platform_id)
        state = await db.scalar(
            select(PlatformTokenState).where(PlatformTokenState.platform_id == platform_id)
        )
        if state is None:
            state = PlatformTokenState(platform_id=platform_id)
            db.add(state)

        state.access_token_encrypted = self._cipher.encrypt_str(token.access_token, aad=aad)
        state.refresh_token_encrypted = (
            self._cipher.encrypt_str(token.refresh_token, aad=aad)
            if token.refresh_token
            else None
        )
        state.token_type = token.token_type
        state.expires_at = token.expires_at
        state.last_refreshed_at = now
        state.last_error = None
        await db.commit()
        await db.refresh(state)
        await self._cache.set(self._cache_key(platform_id), token)
        return state

    async def _record_token_error(
        self,
        db: AsyncSession,
        platform_id: int,
        error_msg: str,
    ) -> None:
        state = await db.scalar(
            select(PlatformTokenState).where(PlatformTokenState.platform_id == platform_id)
        )
        if state is None:
            state = PlatformTokenState(platform_id=platform_id, last_error=error_msg)
            db.add(state)
        else:
            state.last_error = error_msg
        await db.commit()

    def _is_token_usable(
        self,
        token: CachedToken | None,
        *,
        leeway_seconds: int,
        failed_token: str | None = None,
    ) -> bool:
        if token is None or not token.access_token:
            return False
        if failed_token is not None and token.access_token == failed_token:
            return False
        if token.expires_at is None:
            return True
        return utc_now() + timedelta(seconds=leeway_seconds) < token.expires_at

    def _build_injection(
        self,
        *,
        location: str,
        param_name: str,
        prefix: str,
        token_value: str,
        is_dynamic: bool,
    ) -> AuthInjection:
        formatted = f"{prefix}{token_value}"
        if location == "query":
            return AuthInjection(
                query_params={param_name: formatted},
                raw_token=token_value,
                is_dynamic=is_dynamic,
            )
        return AuthInjection(
            headers={param_name: formatted},
            raw_token=token_value,
            is_dynamic=is_dynamic,
        )

    async def send_http_request(
        self,
        method: str,
        url: str,
        *,
        timeout_ms: int,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        form_body: dict[str, Any] | None = None,
        content: bytes | str | None = None,
    ) -> httpx.Response:
        """Send an upstream HTTP request using the configured AsyncClient or an ephemeral client."""
        timeout = httpx.Timeout(timeout_ms / 1000.0)
        kwargs: dict[str, Any] = {
            "headers": headers,
            "params": params,
            "timeout": timeout,
        }
        if json_body is not None:
            kwargs["json"] = json_body
        elif form_body is not None:
            kwargs["data"] = form_body
        elif content is not None:
            kwargs["content"] = content

        if self._external_http_client is not None:
            return await self._external_http_client.request(method, url, **kwargs)
        async with httpx.AsyncClient(timeout=timeout) as client:
            return await client.request(method, url, **kwargs)

    async def _http_request(
        self,
        method: str,
        url: str,
        *,
        timeout_ms: int,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        form_body: dict[str, Any] | None = None,
    ) -> httpx.Response:
        return await self.send_http_request(
            method,
            url,
            timeout_ms=timeout_ms,
            headers=headers,
            params=params,
            json_body=json_body,
            form_body=form_body,
        )

    async def _fetch_oauth2_token(
        self,
        config: OAuth2AuthConfig,
        *,
        timeout_ms: int,
        refresh_token: str | None = None,
        auth_code: str | None = None,
        redirect_uri_override: str | None = None,
    ) -> CachedToken:
        headers: dict[str, str] = {"Accept": "application/json"}
        form: dict[str, str] = dict(config.extra_token_params)

        if auth_code is not None:
            form["grant_type"] = "authorization_code"
            form["code"] = auth_code
            redirect_uri = redirect_uri_override or config.redirect_uri
            if redirect_uri:
                form["redirect_uri"] = redirect_uri
        elif refresh_token is not None:
            form["grant_type"] = "refresh_token"
            form["refresh_token"] = refresh_token
        elif config.grant_type == "client_credentials":
            form["grant_type"] = "client_credentials"
        else:
            raise OAuthAuthorizationRequiredError(
                "OAuth2 authorization_code platform has no refresh_token; "
                "complete admin authorization first."
            )

        if config.scopes and "scope" not in form:
            form["scope"] = " ".join(config.scopes)

        if config.client_auth_method == "basic":
            raw_creds = f"{config.client_id}:{config.client_secret}".encode()
            encoded = base64.b64encode(raw_creds).decode("ascii")
            headers["Authorization"] = f"Basic {encoded}"
        else:
            form["client_id"] = config.client_id
            form["client_secret"] = config.client_secret

        resp = await self.send_http_request(
            "POST",
            config.token_url,
            timeout_ms=timeout_ms,
            headers=headers,
            form_body=form,
        )
        if resp.status_code >= 400:
            raise AuthEngineError(
                f"OAuth2 token request failed with HTTP {resp.status_code}: {resp.text[:300]}"
            )
        try:
            data = resp.json()
        except ValueError as exc:
            raise AuthEngineError("OAuth2 token endpoint did not return valid JSON") from exc

        access_token = data.get("access_token")
        if not access_token or not isinstance(access_token, str):
            raise AuthEngineError("OAuth2 token response missing 'access_token'")

        new_refresh_token = data.get("refresh_token") or refresh_token
        token_type = str(data.get("token_type") or "Bearer")
        expires_at = _parse_expires_at(
            now=utc_now(),
            expires_in_raw=data.get("expires_in"),
            default_ttl_seconds=config.default_ttl_seconds,
        )
        return CachedToken(
            access_token=access_token,
            refresh_token=new_refresh_token,
            token_type=token_type,
            expires_at=expires_at,
        )

    async def _execute_custom_http_spec(
        self,
        spec: CustomHttpRequestSpec,
        config: CustomHttpAuthConfig,
        *,
        timeout_ms: int,
        existing_token: CachedToken | None = None,
    ) -> CachedToken:
        context: dict[str, Any] = {
            "secret": config.secrets,
            "token": {
                "access_token": existing_token.access_token if existing_token else "",
                "refresh_token": (
                    existing_token.refresh_token
                    if existing_token and existing_token.refresh_token
                    else ""
                ),
            },
        }
        rendered_url = str(_render_template(spec.url, context))
        rendered_headers = {
            k: str(v) for k, v in _render_template(spec.headers, context).items()
        }
        rendered_query = _render_template(spec.query, context)
        rendered_body = _render_template(spec.body, context)

        json_body = rendered_body if spec.body_type == "json" else None
        form_body = rendered_body if spec.body_type == "form" else None

        resp = await self.send_http_request(
            spec.method,
            rendered_url,
            timeout_ms=timeout_ms,
            headers=rendered_headers,
            params=rendered_query or None,
            json_body=json_body,
            form_body=form_body,
        )
        if resp.status_code >= 400:
            raise AuthEngineError(
                f"Custom token HTTP request failed with HTTP {resp.status_code}: {resp.text[:300]}"
            )
        try:
            data = resp.json()
        except ValueError as exc:
            raise AuthEngineError("Custom token HTTP endpoint did not return valid JSON") from exc

        mapping = config.response_mapping
        access_token = extract_json_path(data, mapping.access_token_path)
        if not access_token or not isinstance(access_token, str):
            raise AuthEngineError(
                f"Custom token response missing string at '{mapping.access_token_path}'"
            )

        refresh_token = existing_token.refresh_token if existing_token else None
        if mapping.refresh_token_path:
            extracted_rt = extract_json_path(data, mapping.refresh_token_path)
            if isinstance(extracted_rt, str) and extracted_rt:
                refresh_token = extracted_rt

        expires_in_raw = (
            extract_json_path(data, mapping.expires_in_path)
            if mapping.expires_in_path
            else None
        )
        expires_at_raw = (
            extract_json_path(data, mapping.expires_at_path)
            if mapping.expires_at_path
            else None
        )
        expires_at = _parse_expires_at(
            now=utc_now(),
            expires_in_raw=expires_in_raw,
            expires_at_raw=expires_at_raw,
            fixed_ttl_seconds=mapping.fixed_ttl_seconds,
            default_ttl_seconds=config.default_ttl_seconds,
        )
        return CachedToken(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="Bearer",
            expires_at=expires_at,
        )

    async def _fetch_dynamic_token(
        self,
        db: AsyncSession,
        platform: Platform,
        config: OAuth2AuthConfig | CustomHttpAuthConfig,
        existing: CachedToken | None,
    ) -> CachedToken:
        # Always reload latest DB token state so rotating refresh tokens survive multi-worker runs
        db_token = await self._load_db_token(db, platform.id)
        latest = db_token or existing

        if isinstance(config, OAuth2AuthConfig):
            refresh_tok = (
                (db_token.refresh_token if db_token else None)
                or (existing.refresh_token if existing else None)
            )
            if refresh_tok:
                try:
                    return await self._fetch_oauth2_token(
                        config,
                        timeout_ms=platform.timeout_ms,
                        refresh_token=refresh_tok,
                    )
                except AuthEngineError:
                    if config.grant_type == "authorization_code":
                        raise
                    # Fall back to client_credentials if refresh_token failed
            return await self._fetch_oauth2_token(config, timeout_ms=platform.timeout_ms)

        # CustomHttpAuthConfig
        if config.refresh_request is not None and latest is not None:
            try:
                return await self._execute_custom_http_spec(
                    config.refresh_request,
                    config,
                    timeout_ms=platform.timeout_ms,
                    existing_token=latest,
                )
            except AuthEngineError:
                # Fall back to primary token_request if refresh_request fails
                pass

        return await self._execute_custom_http_spec(
            config.token_request,
            config,
            timeout_ms=platform.timeout_ms,
            existing_token=latest,
        )

    async def get_injection(
        self,
        db: AsyncSession,
        platform: Platform,
        *,
        force_refresh: bool = False,
        failed_token: str | None = None,
        ignore_cache: bool = False,
        config: PlatformAuthConfigPayload | None = None,
    ) -> AuthInjection:
        """Resolve upstream auth headers/query params with single-flight proactive renewal."""
        resolved_cfg = config
        if resolved_cfg is None:
            resolved_cfg, _ = await self.load_auth_config(db, platform.id)

        if isinstance(resolved_cfg, NoneAuthConfig):
            return AuthInjection(is_dynamic=False)

        if isinstance(resolved_cfg, StaticAuthConfig):
            return self._build_injection(
                location=resolved_cfg.location,
                param_name=resolved_cfg.param_name,
                prefix=resolved_cfg.value_prefix,
                token_value=resolved_cfg.value,
                is_dynamic=False,
            )

        # Dynamic auth: OAuth2 or Custom HTTP
        leeway = resolved_cfg.refresh_leeway_seconds
        if not force_refresh and not ignore_cache:
            cached = await self._load_cached_or_db_token(db, platform.id)
            if self._is_token_usable(cached, leeway_seconds=leeway, failed_token=failed_token):
                assert cached is not None
                return self._build_injection(
                    location=resolved_cfg.inject_location,
                    param_name=resolved_cfg.inject_name,
                    prefix=resolved_cfg.inject_prefix,
                    token_value=cached.access_token,
                    is_dynamic=True,
                )

        # Acquire platform-scoped single-flight lock to prevent thundering-herd refresh storms
        async with self._cache.lock(self._cache_key(platform.id)):
            current = await self._load_cached_or_db_token(db, platform.id)
            # Double-check: another coroutine may have already refreshed the token while we waited
            if not ignore_cache and self._is_token_usable(
                current,
                leeway_seconds=leeway,
                failed_token=failed_token,
            ):
                assert current is not None
                return self._build_injection(
                    location=resolved_cfg.inject_location,
                    param_name=resolved_cfg.inject_name,
                    prefix=resolved_cfg.inject_prefix,
                    token_value=current.access_token,
                    is_dynamic=True,
                )

            try:
                new_token = await self._fetch_dynamic_token(db, platform, resolved_cfg, current)
            except AuthEngineError as exc:
                await self._record_token_error(db, platform.id, str(exc))
                raise

            await self._persist_token(db, platform.id, new_token)
            return self._build_injection(
                location=resolved_cfg.inject_location,
                param_name=resolved_cfg.inject_name,
                prefix=resolved_cfg.inject_prefix,
                token_value=new_token.access_token,
                is_dynamic=True,
            )

    async def execute_http_with_auth_retry(
        self,
        db: AsyncSession,
        platform: Platform,
        request_fn: Callable[[AuthInjection], Awaitable[httpx.Response]],
    ) -> tuple[httpx.Response, bool]:
        """Execute an upstream HTTP call with auth injection and single refresh-replay."""
        config, _ = await self.load_auth_config(db, platform.id)
        injection = await self.get_injection(db, platform, config=config)
        response = await request_fn(injection)

        if not isinstance(config, (OAuth2AuthConfig, CustomHttpAuthConfig)):
            return response, False

        body_json: Any = None
        if config.invalid_rules.body_rules:
            try:
                body_json = response.json()
            except ValueError:
                body_json = None

        if not is_token_invalid_response(config.invalid_rules, response.status_code, body_json):
            return response, False

        # Passive refresh + single replay using single-flight coordination
        refreshed_injection = await self.get_injection(
            db,
            platform,
            force_refresh=True,
            failed_token=injection.raw_token,
            config=config,
        )
        replayed = await request_fn(refreshed_injection)
        return replayed, True

    # -----------------------------------------------------------------------
    # OAuth2 Admin Authorization Code Helpers
    # -----------------------------------------------------------------------

    def _prune_oauth_nonces(self, now_ts: float) -> None:
        expired = [k for k, exp in self._oauth_state_nonces.items() if exp <= now_ts]
        for k in expired:
            self._oauth_state_nonces.pop(k, None)

    def build_oauth_authorize_url(
        self,
        platform_id: int,
        config: OAuth2AuthConfig,
        *,
        jwt_secret: str,
        jwt_algorithm: str = "HS256",
        redirect_uri_override: str | None = None,
    ) -> tuple[str, str]:
        if config.grant_type != "authorization_code" or not config.authorize_url:
            raise AuthEngineError(
                "Platform is not configured with OAuth2 authorization_code grant_type"
            )
        now = utc_now()
        exp_ts = (now + timedelta(minutes=15)).timestamp()
        nonce = secrets.token_urlsafe(16)
        self._prune_oauth_nonces(now.timestamp())
        self._oauth_state_nonces[nonce] = exp_ts

        state = jwt.encode(
            {
                "purpose": "fieldscope_oauth_state",
                "pid": platform_id,
                "nonce": nonce,
                "iat": int(now.timestamp()),
                "exp": int(exp_ts),
            },
            jwt_secret,
            algorithm=jwt_algorithm,
        )
        params: dict[str, str] = {
            "response_type": "code",
            "client_id": config.client_id,
            "state": state,
        }
        redirect_uri = redirect_uri_override or config.redirect_uri
        if redirect_uri:
            params["redirect_uri"] = redirect_uri
        if config.scopes:
            params["scope"] = " ".join(config.scopes)

        sep = "&" if "?" in config.authorize_url else "?"
        return f"{config.authorize_url}{sep}{urlencode(params)}", state

    def verify_oauth_state(
        self,
        state: str,
        *,
        expected_platform_id: int,
        jwt_secret: str,
        jwt_algorithm: str = "HS256",
    ) -> None:
        try:
            payload = jwt.decode(state, jwt_secret, algorithms=[jwt_algorithm])
        except jwt.PyJWTError as exc:
            raise AuthEngineError("Invalid or expired OAuth state parameter") from exc
        if (
            payload.get("purpose") != "fieldscope_oauth_state"
            or payload.get("pid") != expected_platform_id
        ):
            raise AuthEngineError("OAuth state does not match target platform")

        nonce = payload.get("nonce")
        now_ts = utc_now().timestamp()
        self._prune_oauth_nonces(now_ts)
        if not isinstance(nonce, str) or nonce not in self._oauth_state_nonces:
            raise AuthEngineError("OAuth state has already been used or is unrecognized")
        self._oauth_state_nonces.pop(nonce, None)

    async def exchange_oauth_code(
        self,
        db: AsyncSession,
        platform: Platform,
        *,
        code: str,
        state: str,
        jwt_secret: str,
        jwt_algorithm: str = "HS256",
        redirect_uri_override: str | None = None,
    ) -> PlatformTokenState:
        config, _ = await self.load_auth_config(db, platform.id)
        if not isinstance(config, OAuth2AuthConfig) or config.grant_type != "authorization_code":
            raise AuthEngineError(
                "Platform is not configured with OAuth2 authorization_code grant_type"
            )
        self.verify_oauth_state(
            state,
            expected_platform_id=platform.id,
            jwt_secret=jwt_secret,
            jwt_algorithm=jwt_algorithm,
        )
        try:
            token = await self._fetch_oauth2_token(
                config,
                timeout_ms=platform.timeout_ms,
                auth_code=code,
                redirect_uri_override=redirect_uri_override,
            )
        except AuthEngineError as exc:
            await self._record_token_error(db, platform.id, str(exc))
            raise
        return await self._persist_token(db, platform.id, token)
