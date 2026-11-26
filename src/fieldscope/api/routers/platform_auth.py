from __future__ import annotations

import time
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fieldscope.api.deps import get_app_settings, require_permissions
from fieldscope.auth_engine.engine import (
    AuthEngine,
    AuthEngineError,
    AuthInjection,
    OAuthAuthorizationRequiredError,
    mask_auth_config,
    mask_token_preview,
)
from fieldscope.core.config import Settings
from fieldscope.db.base import utc_now
from fieldscope.db.models import Platform, PlatformTokenState, User
from fieldscope.db.session import get_db
from fieldscope.schemas.platform_auth import (
    OAuth2AuthConfig,
    OAuthAuthorizeUrlResponse,
    OAuthCallbackRequest,
    PlatformAuthConfigPayload,
    PlatformAuthConfigRead,
    PlatformAuthTestRequest,
    PlatformAuthTestResponse,
    PlatformTokenStatusRead,
)

router = APIRouter(prefix="/api/v1/admin/platforms", tags=["platform-auth"])


def get_auth_engine(request: Request) -> AuthEngine:
    return request.app.state.auth_engine


async def _get_platform_or_404(db: AsyncSession, platform_id: int) -> Platform:
    platform = await db.scalar(select(Platform).where(Platform.id == platform_id))
    if platform is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Platform not found")
    return platform


async def _build_token_status(
    db: AsyncSession,
    auth_engine: AuthEngine,
    platform_id: int,
) -> PlatformTokenStatusRead:
    cfg, _ = await auth_engine.load_auth_config(db, platform_id)
    state = await db.scalar(
        select(PlatformTokenState).where(PlatformTokenState.platform_id == platform_id)
    )
    if state is None:
        return PlatformTokenStatusRead(
            platform_id=platform_id,
            auth_type=cfg.auth_type,
            has_access_token=False,
            has_refresh_token=False,
            is_expired=False,
        )

    preview: str | None = None
    if state.access_token_encrypted:
        try:
            decrypted = auth_engine._cipher.decrypt_str(
                state.access_token_encrypted,
                aad=auth_engine._token_aad(platform_id),
            )
            preview = mask_token_preview(decrypted)
        except Exception:
            preview = "***"

    now = utc_now()
    is_expired = bool(state.expires_at is not None and state.expires_at <= now)
    return PlatformTokenStatusRead(
        platform_id=platform_id,
        auth_type=cfg.auth_type,
        has_access_token=bool(state.access_token_encrypted),
        has_refresh_token=bool(state.refresh_token_encrypted),
        token_preview=preview,
        token_type=state.token_type,
        expires_at=state.expires_at,
        is_expired=is_expired,
        last_refreshed_at=state.last_refreshed_at,
        last_error=state.last_error,
    )


@router.get("/{platform_id}/auth", response_model=PlatformAuthConfigRead)
async def get_platform_auth_config(
    platform_id: int,
    _admin: User = Depends(require_permissions("platform:read")),
    db: AsyncSession = Depends(get_db),
    auth_engine: AuthEngine = Depends(get_auth_engine),
) -> PlatformAuthConfigRead:
    await _get_platform_or_404(db, platform_id)
    cfg, row = await auth_engine.load_auth_config(db, platform_id)
    return PlatformAuthConfigRead(
        platform_id=platform_id,
        auth_type=cfg.auth_type,
        config=mask_auth_config(cfg),
        updated_at=row.updated_at if row else None,
    )


@router.put("/{platform_id}/auth", response_model=PlatformAuthConfigRead)
async def upsert_platform_auth_config(
    platform_id: int,
    body: PlatformAuthConfigPayload,
    _admin: User = Depends(require_permissions("platform:write")),
    db: AsyncSession = Depends(get_db),
    auth_engine: AuthEngine = Depends(get_auth_engine),
) -> PlatformAuthConfigRead:
    await _get_platform_or_404(db, platform_id)
    saved_cfg, row = await auth_engine.save_auth_config(db, platform_id, body)
    return PlatformAuthConfigRead(
        platform_id=platform_id,
        auth_type=saved_cfg.auth_type,
        config=mask_auth_config(saved_cfg),
        updated_at=row.updated_at,
    )


@router.get("/{platform_id}/auth/token-status", response_model=PlatformTokenStatusRead)
async def get_platform_token_status(
    platform_id: int,
    _admin: User = Depends(require_permissions("platform:read")),
    db: AsyncSession = Depends(get_db),
    auth_engine: AuthEngine = Depends(get_auth_engine),
) -> PlatformTokenStatusRead:
    await _get_platform_or_404(db, platform_id)
    return await _build_token_status(db, auth_engine, platform_id)


@router.post("/{platform_id}/auth/refresh", response_model=PlatformTokenStatusRead)
async def refresh_platform_token(
    platform_id: int,
    _admin: User = Depends(require_permissions("platform:write")),
    db: AsyncSession = Depends(get_db),
    auth_engine: AuthEngine = Depends(get_auth_engine),
) -> PlatformTokenStatusRead:
    platform = await _get_platform_or_404(db, platform_id)
    cfg, _ = await auth_engine.load_auth_config(db, platform_id)
    if cfg.auth_type not in ("oauth2", "custom_http"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Auth type '{cfg.auth_type}' does not support dynamic token refresh",
        )
    try:
        await auth_engine.get_injection(
            db,
            platform,
            force_refresh=True,
            ignore_cache=True,
        )
    except OAuthAuthorizationRequiredError as exc:
        raise HTTPException(
            status_code=status.HTTP_412_PRECONDITION_FAILED,
            detail=str(exc),
        ) from exc
    except AuthEngineError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(exc),
        ) from exc

    return await _build_token_status(db, auth_engine, platform_id)


@router.get(
    "/{platform_id}/auth/oauth/authorize-url",
    response_model=OAuthAuthorizeUrlResponse,
)
async def get_oauth_authorize_url(
    platform_id: int,
    redirect_uri: str | None = Query(default=None),
    _admin: User = Depends(require_permissions("platform:write")),
    db: AsyncSession = Depends(get_db),
    auth_engine: AuthEngine = Depends(get_auth_engine),
    settings: Settings = Depends(get_app_settings),
) -> OAuthAuthorizeUrlResponse:
    await _get_platform_or_404(db, platform_id)
    cfg, _ = await auth_engine.load_auth_config(db, platform_id)
    if not isinstance(cfg, OAuth2AuthConfig) or cfg.grant_type != "authorization_code":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Platform is not configured with OAuth2 authorization_code mode",
        )
    try:
        url, state = auth_engine.build_oauth_authorize_url(
            platform_id,
            cfg,
            jwt_secret=settings.secret_key,
            jwt_algorithm=settings.jwt_algorithm,
            redirect_uri_override=redirect_uri,
        )
    except AuthEngineError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return OAuthAuthorizeUrlResponse(authorize_url=url, state=state)


@router.post("/{platform_id}/auth/oauth/callback", response_model=PlatformTokenStatusRead)
async def complete_oauth_callback(
    platform_id: int,
    body: OAuthCallbackRequest,
    _admin: User = Depends(require_permissions("platform:write")),
    db: AsyncSession = Depends(get_db),
    auth_engine: AuthEngine = Depends(get_auth_engine),
    settings: Settings = Depends(get_app_settings),
) -> PlatformTokenStatusRead:
    platform = await _get_platform_or_404(db, platform_id)
    try:
        await auth_engine.exchange_oauth_code(
            db,
            platform,
            code=body.code,
            state=body.state,
            jwt_secret=settings.secret_key,
            jwt_algorithm=settings.jwt_algorithm,
            redirect_uri_override=body.redirect_uri,
        )
    except AuthEngineError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    return await _build_token_status(db, auth_engine, platform_id)


@router.post("/{platform_id}/auth/test", response_model=PlatformAuthTestResponse)
async def test_platform_auth(
    platform_id: int,
    body: PlatformAuthTestRequest,
    _admin: User = Depends(require_permissions("platform:write")),
    db: AsyncSession = Depends(get_db),
    auth_engine: AuthEngine = Depends(get_auth_engine),
) -> PlatformAuthTestResponse:
    """Execute a live test request against the platform using configured auth & retry loop."""
    platform = await _get_platform_or_404(db, platform_id)
    target_path = body.path.lstrip("/")
    url = f"{platform.base_url}/{target_path}" if target_path else platform.base_url

    started = time.perf_counter()

    async def _send(injection: AuthInjection) -> httpx.Response:
        merged_headers = {**platform.extra_headers, **body.headers, **injection.headers}
        merged_query = {**body.query, **injection.query_params}
        return await auth_engine._http_request(
            body.method,
            url,
            timeout_ms=platform.timeout_ms,
            headers=merged_headers,
            params=merged_query or None,
            json_body=body.body if body.method in ("POST", "PUT", "PATCH") else None,
        )

    try:
        resp, retried = await auth_engine.execute_http_with_auth_retry(db, platform, _send)
    except OAuthAuthorizationRequiredError as exc:
        raise HTTPException(
            status_code=status.HTTP_412_PRECONDITION_FAILED,
            detail=str(exc),
        ) from exc
    except (AuthEngineError, httpx.HTTPError) as exc:
        latency_ms = int((time.perf_counter() - started) * 1000)
        return PlatformAuthTestResponse(
            ok=False,
            upstream_status=0,
            retried_after_refresh=False,
            latency_ms=latency_ms,
            error=str(exc),
        )

    latency_ms = int((time.perf_counter() - started) * 1000)
    preview: Any
    try:
        preview = resp.json()
    except ValueError:
        preview = resp.text[:500]

    return PlatformAuthTestResponse(
        ok=200 <= resp.status_code < 400,
        upstream_status=resp.status_code,
        retried_after_refresh=retried,
        latency_ms=latency_ms,
        response_preview=preview,
    )
