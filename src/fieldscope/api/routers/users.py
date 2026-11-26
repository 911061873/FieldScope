from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from fieldscope.api.deps import require_permissions
from fieldscope.core.security import USER_API_KEY_PREFIX, generate_api_key, hash_password
from fieldscope.db.models import ExternalRole, PlatformRole, User, UserApiKey
from fieldscope.db.session import get_db
from fieldscope.schemas.common import MessageResponse
from fieldscope.schemas.iam import (
    UserApiKeyCreate,
    UserApiKeyCreated,
    UserApiKeyRead,
    UserCreate,
    UserRead,
    UserRoleAssignRequest,
    UserUpdate,
)

router = APIRouter(prefix="/api/v1/admin/users", tags=["users"])


async def _load_user_full(db: AsyncSession, user_id: int) -> User | None:
    return await db.scalar(
        select(User)
        .where(User.id == user_id)
        .options(
            selectinload(User.platform_roles),
            selectinload(User.external_roles),
        )
    )


async def _resolve_platform_roles(db: AsyncSession, role_ids: list[int]) -> list[PlatformRole]:
    if not role_ids:
        return []
    unique_ids = list(dict.fromkeys(role_ids))
    roles = (await db.scalars(select(PlatformRole).where(PlatformRole.id.in_(unique_ids)))).all()
    found = {r.id for r in roles}
    missing = [rid for rid in unique_ids if rid not in found]
    if missing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown platform role IDs: {missing}",
        )
    return list(roles)


async def _resolve_external_roles(db: AsyncSession, role_ids: list[int]) -> list[ExternalRole]:
    if not role_ids:
        return []
    unique_ids = list(dict.fromkeys(role_ids))
    roles = (await db.scalars(select(ExternalRole).where(ExternalRole.id.in_(unique_ids)))).all()
    found = {r.id for r in roles}
    missing = [rid for rid in unique_ids if rid not in found]
    if missing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown external role IDs: {missing}",
        )
    return list(roles)


@router.get("", response_model=list[UserRead])
async def list_users(
    _admin: User = Depends(require_permissions("user:read")),
    db: AsyncSession = Depends(get_db),
) -> list[UserRead]:
    rows = (
        await db.scalars(
            select(User)
            .options(
                selectinload(User.platform_roles),
                selectinload(User.external_roles),
            )
            .order_by(User.id.asc())
        )
    ).all()
    return [UserRead.model_validate(u) for u in rows]


@router.post("", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def create_user(
    body: UserCreate,
    _admin: User = Depends(require_permissions("user:write")),
    db: AsyncSession = Depends(get_db),
) -> UserRead:
    exists = await db.scalar(select(User.id).where(User.username == body.username))
    if exists is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Username '{body.username}' already exists",
        )

    platform_roles = await _resolve_platform_roles(db, body.platform_role_ids)
    external_roles = await _resolve_external_roles(db, body.external_role_ids)

    user = User(
        username=body.username,
        password_hash=hash_password(body.password),
        display_name=body.display_name or body.username,
        email=body.email,
        department=body.department,
        attributes=body.attributes,
        is_active=body.is_active,
        is_superuser=body.is_superuser,
        platform_roles=platform_roles,
        external_roles=external_roles,
    )
    db.add(user)
    await db.commit()
    loaded = await _load_user_full(db, user.id)
    return UserRead.model_validate(loaded)


@router.get("/{user_id}", response_model=UserRead)
async def get_user(
    user_id: int,
    _admin: User = Depends(require_permissions("user:read")),
    db: AsyncSession = Depends(get_db),
) -> UserRead:
    user = await _load_user_full(db, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserRead.model_validate(user)


@router.patch("/{user_id}", response_model=UserRead)
async def update_user(
    user_id: int,
    body: UserUpdate,
    admin: User = Depends(require_permissions("user:write")),
    db: AsyncSession = Depends(get_db),
) -> UserRead:
    user = await _load_user_full(db, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if user.id == admin.id and body.is_active is False:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot disable your own active account",
        )

    if body.password is not None:
        user.password_hash = hash_password(body.password)
    if body.display_name is not None:
        user.display_name = body.display_name
    if body.email is not None:
        user.email = body.email
    if body.department is not None:
        user.department = body.department
    if body.attributes is not None:
        user.attributes = body.attributes
    if body.is_active is not None:
        user.is_active = body.is_active
    if body.is_superuser is not None:
        user.is_superuser = body.is_superuser

    await db.commit()
    loaded = await _load_user_full(db, user.id)
    return UserRead.model_validate(loaded)


@router.delete("/{user_id}", response_model=MessageResponse)
async def delete_user(
    user_id: int,
    admin: User = Depends(require_permissions("user:write")),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    if user_id == admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account",
        )
    user = await db.scalar(select(User).where(User.id == user_id))
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    await db.delete(user)
    await db.commit()
    return MessageResponse(message="User deleted")


@router.put("/{user_id}/platform-roles", response_model=UserRead)
async def assign_platform_roles(
    user_id: int,
    body: UserRoleAssignRequest,
    _admin: User = Depends(require_permissions("user:write")),
    db: AsyncSession = Depends(get_db),
) -> UserRead:
    user = await _load_user_full(db, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    user.platform_roles = await _resolve_platform_roles(db, body.role_ids)
    await db.commit()
    loaded = await _load_user_full(db, user.id)
    return UserRead.model_validate(loaded)


@router.put("/{user_id}/external-roles", response_model=UserRead)
async def assign_external_roles(
    user_id: int,
    body: UserRoleAssignRequest,
    _admin: User = Depends(require_permissions("user:write")),
    db: AsyncSession = Depends(get_db),
) -> UserRead:
    user = await _load_user_full(db, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    user.external_roles = await _resolve_external_roles(db, body.role_ids)
    await db.commit()
    loaded = await _load_user_full(db, user.id)
    return UserRead.model_validate(loaded)


@router.get("/{user_id}/api-keys", response_model=list[UserApiKeyRead])
async def list_user_api_keys(
    user_id: int,
    _admin: User = Depends(require_permissions("user:read")),
    db: AsyncSession = Depends(get_db),
) -> list[UserApiKeyRead]:
    user_exists = await db.scalar(select(User.id).where(User.id == user_id))
    if user_exists is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    rows = (
        await db.scalars(
            select(UserApiKey)
            .where(UserApiKey.user_id == user_id)
            .order_by(UserApiKey.id.desc())
        )
    ).all()
    return [UserApiKeyRead.model_validate(k) for k in rows]


@router.post(
    "/{user_id}/api-keys",
    response_model=UserApiKeyCreated,
    status_code=status.HTTP_201_CREATED,
)
async def create_user_api_key(
    user_id: int,
    body: UserApiKeyCreate,
    _admin: User = Depends(require_permissions("user:write")),
    db: AsyncSession = Depends(get_db),
) -> UserApiKeyCreated:
    user_exists = await db.scalar(select(User.id).where(User.id == user_id))
    if user_exists is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    plain_key, key_prefix, key_hash = generate_api_key(USER_API_KEY_PREFIX)
    api_key = UserApiKey(
        user_id=user_id,
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


@router.delete("/{user_id}/api-keys/{key_id}", response_model=MessageResponse)
async def revoke_user_api_key(
    user_id: int,
    key_id: int,
    _admin: User = Depends(require_permissions("user:write")),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    api_key = await db.scalar(
        select(UserApiKey).where(UserApiKey.id == key_id, UserApiKey.user_id == user_id)
    )
    if api_key is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")
    await db.delete(api_key)
    await db.commit()
    return MessageResponse(message="API key revoked")
