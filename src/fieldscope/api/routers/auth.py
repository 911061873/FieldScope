from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fieldscope.api.deps import (
    compute_user_platform_permissions,
    get_app_settings,
    get_current_user,
)
from fieldscope.core.config import Settings
from fieldscope.core.security import (
    USER_API_KEY_PREFIX,
    create_access_token,
    generate_api_key,
    verify_password,
)
from fieldscope.db.models import User, UserApiKey
from fieldscope.db.session import get_db
from fieldscope.schemas.auth import CurrentUserResponse, LoginRequest, TokenResponse
from fieldscope.schemas.common import MessageResponse, RoleBrief
from fieldscope.schemas.iam import UserApiKeyCreate, UserApiKeyCreated, UserApiKeyRead

router = APIRouter(prefix="/api/v1/admin/auth", tags=["auth"])


@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_app_settings),
) -> TokenResponse:
    user = await db.scalar(select(User).where(User.username == body.username))
    if user is None or not verify_password(body.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled",
        )

    token, expires_at = create_access_token(
        subject=str(user.id),
        secret_key=settings.secret_key,
        algorithm=settings.jwt_algorithm,
        expires_minutes=settings.jwt_expire_minutes,
        extra_claims={"username": user.username},
    )
    return TokenResponse(access_token=token, expires_at=expires_at)


@router.get("/me", response_model=CurrentUserResponse)
async def get_me(current_user: User = Depends(get_current_user)) -> CurrentUserResponse:
    perms = sorted(compute_user_platform_permissions(current_user))
    return CurrentUserResponse(
        id=current_user.id,
        username=current_user.username,
        display_name=current_user.display_name,
        email=current_user.email,
        department=current_user.department,
        attributes=current_user.attributes,
        is_active=current_user.is_active,
        is_superuser=current_user.is_superuser,
        platform_roles=[RoleBrief.model_validate(r) for r in current_user.platform_roles],
        external_roles=[RoleBrief.model_validate(r) for r in current_user.external_roles],
        platform_permissions=perms,
    )


@router.get("/me/api-keys", response_model=list[UserApiKeyRead])
async def list_my_api_keys(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[UserApiKeyRead]:
    rows = (
        await db.scalars(
            select(UserApiKey)
            .where(UserApiKey.user_id == current_user.id)
            .order_by(UserApiKey.id.desc())
        )
    ).all()
    return [UserApiKeyRead.model_validate(k) for k in rows]


@router.post("/me/api-keys", response_model=UserApiKeyCreated, status_code=status.HTTP_201_CREATED)
async def create_my_api_key(
    body: UserApiKeyCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> UserApiKeyCreated:
    plain_key, key_prefix, key_hash = generate_api_key(USER_API_KEY_PREFIX)
    api_key = UserApiKey(
        user_id=current_user.id,
        name=body.name,
        key_prefix=key_prefix,
        key_hash=key_hash,
        expires_at=body.expires_at,
        is_active=True,
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)
    return UserApiKeyCreated(
        **UserApiKeyRead.model_validate(api_key).model_dump(),
        plain_key=plain_key,
    )


@router.delete("/me/api-keys/{key_id}", response_model=MessageResponse)
async def revoke_my_api_key(
    key_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    api_key = await db.scalar(
        select(UserApiKey).where(
            UserApiKey.id == key_id,
            UserApiKey.user_id == current_user.id,
        )
    )
    if api_key is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")
    await db.delete(api_key)
    await db.commit()
    return MessageResponse(message="API key revoked")
