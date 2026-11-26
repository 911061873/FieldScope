from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from fieldscope.core.config import Settings
from fieldscope.core.permissions import ALL_PERMISSION_CODES
from fieldscope.core.security import (
    APP_API_KEY_PREFIX,
    USER_API_KEY_PREFIX,
    decode_access_token,
    hash_api_key,
)
from fieldscope.db.base import utc_now
from fieldscope.db.models import ExternalApp, PlatformRole, User, UserApiKey
from fieldscope.db.session import get_db

bearer_scheme = HTTPBearer(auto_error=False)


def get_app_settings(request: Request) -> Settings:
    return request.app.state.settings


def compute_user_platform_permissions(user: User) -> set[str]:
    if user.is_superuser:
        return set(ALL_PERMISSION_CODES)
    perms: set[str] = set()
    for role in user.platform_roles:
        for perm in role.permissions:
            perms.add(perm.code)
    return perms


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_app_settings),
) -> User:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Bearer token",
        )

    try:
        payload = decode_access_token(
            credentials.credentials,
            secret_key=settings.secret_key,
            algorithm=settings.jwt_algorithm,
        )
        user_id = int(payload["sub"])
    except (jwt.PyJWTError, KeyError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
        ) from exc

    stmt = (
        select(User)
        .where(User.id == user_id)
        .options(
            selectinload(User.platform_roles).selectinload(PlatformRole.permissions),
            selectinload(User.external_roles),
        )
    )
    user = await db.scalar(stmt)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )
    return user


def require_permissions(*required_codes: str) -> Callable[..., User]:
    """Dependency enforcing that the logged-in user holds all specified platform permissions."""

    async def _checker(current_user: User = Depends(get_current_user)) -> User:
        effective = compute_user_platform_permissions(current_user)
        missing = [code for code in required_codes if code not in effective]
        if missing:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing platform permissions: {', '.join(missing)}",
            )
        return current_user

    return _checker


@dataclass
class DataPlanePrincipal:
    """Resolved identity for runtime data-plane HTTP / MCP requests."""

    auth_mode: str  # "user_api_key" | "external_app_delegation"
    user: User
    app: ExternalApp | None = None


async def resolve_data_plane_principal(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_app_settings),
) -> DataPlanePrincipal:
    """Resolve data-plane caller via User API Key (fs_usr_*) or External App Key (fs_app_*)."""
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Bearer API key for data-plane access",
        )

    raw_key = credentials.credentials.strip()
    now = utc_now()
    debounce = max(0, settings.last_used_debounce_seconds)

    if raw_key.startswith(USER_API_KEY_PREFIX):
        key_hash = hash_api_key(raw_key)
        api_key = await db.scalar(
            select(UserApiKey)
            .where(UserApiKey.key_hash == key_hash)
            .options(
                selectinload(UserApiKey.user).selectinload(User.external_roles),
            )
        )
        if api_key is None or not api_key.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or revoked user API key",
            )
        if api_key.expires_at is not None and api_key.expires_at <= now:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User API key has expired",
            )
        if api_key.user is None or not api_key.user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Associated user is inactive",
            )
        if (
            api_key.last_used_at is None
            or (now - api_key.last_used_at).total_seconds() >= debounce
        ):
            api_key.last_used_at = now
            await db.commit()
        return DataPlanePrincipal(auth_mode="user_api_key", user=api_key.user, app=None)

    if raw_key.startswith(APP_API_KEY_PREFIX):
        key_hash = hash_api_key(raw_key)
        app = await db.scalar(select(ExternalApp).where(ExternalApp.key_hash == key_hash))
        if app is None or not app.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or inactive external app key",
            )

        user_ident = request.headers.get(app.user_identity_header)
        if not user_ident:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Missing delegated user header: {app.user_identity_header}",
            )
        user_ident = user_ident.strip()

        # Match delegated identity strictly by username to avoid numeric-ID ambiguity
        stmt = (
            select(User)
            .where(User.username == user_ident)
            .options(selectinload(User.external_roles))
        )
        user = await db.scalar(stmt)

        if user is None or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Delegated user '{user_ident}' not found or inactive",
            )

        # Enforce delegation scope if allowed_user_ids or allowed_external_role_ids is configured
        allowed_uids = set(app.allowed_user_ids or [])
        allowed_rids = set(app.allowed_external_role_ids or [])
        if allowed_uids or allowed_rids:
            user_active_rids = {r.id for r in user.external_roles if r.is_active}
            if user.id not in allowed_uids and not (user_active_rids & allowed_rids):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=(
                        f"External app '{app.app_code}' is not permitted to delegate "
                        f"user '{user.username}'"
                    ),
                )

        if app.last_used_at is None or (now - app.last_used_at).total_seconds() >= debounce:
            app.last_used_at = now
            await db.commit()
        return DataPlanePrincipal(auth_mode="external_app_delegation", user=user, app=app)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unsupported API key prefix; expected fs_usr_ or fs_app_",
    )
