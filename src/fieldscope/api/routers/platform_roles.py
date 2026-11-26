from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from fieldscope.api.deps import require_permissions
from fieldscope.db.models import PlatformPermission, PlatformRole, User
from fieldscope.db.session import get_db
from fieldscope.schemas.common import MessageResponse
from fieldscope.schemas.iam import (
    PlatformPermissionRead,
    PlatformRoleCreate,
    PlatformRoleRead,
    PlatformRoleUpdate,
)

router = APIRouter(prefix="/api/v1/admin", tags=["platform-rbac"])


async def _load_permissions_by_codes(
    db: AsyncSession,
    codes: list[str],
) -> list[PlatformPermission]:
    if not codes:
        return []
    unique_codes = list(dict.fromkeys(codes))
    perms = (
        await db.scalars(
            select(PlatformPermission).where(PlatformPermission.code.in_(unique_codes))
        )
    ).all()
    found = {p.code for p in perms}
    unknown = [c for c in unique_codes if c not in found]
    if unknown:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown platform permission codes: {', '.join(unknown)}",
        )
    return list(perms)


@router.get("/platform-permissions", response_model=list[PlatformPermissionRead])
async def list_platform_permissions(
    _user: User = Depends(require_permissions("platform_role:read")),
    db: AsyncSession = Depends(get_db),
) -> list[PlatformPermissionRead]:
    rows = (
        await db.scalars(
            select(PlatformPermission).order_by(
                PlatformPermission.module,
                PlatformPermission.code,
            )
        )
    ).all()
    return [PlatformPermissionRead.model_validate(p) for p in rows]


@router.get("/platform-roles", response_model=list[PlatformRoleRead])
async def list_platform_roles(
    _user: User = Depends(require_permissions("platform_role:read")),
    db: AsyncSession = Depends(get_db),
) -> list[PlatformRoleRead]:
    rows = (
        await db.scalars(
            select(PlatformRole)
            .options(selectinload(PlatformRole.permissions))
            .order_by(PlatformRole.id.asc())
        )
    ).all()
    return [PlatformRoleRead.model_validate(r) for r in rows]


@router.post(
    "/platform-roles",
    response_model=PlatformRoleRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_platform_role(
    body: PlatformRoleCreate,
    _user: User = Depends(require_permissions("platform_role:write")),
    db: AsyncSession = Depends(get_db),
) -> PlatformRoleRead:
    exists = await db.scalar(select(PlatformRole.id).where(PlatformRole.code == body.code))
    if exists is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Platform role code '{body.code}' already exists",
        )
    perms = await _load_permissions_by_codes(db, body.permission_codes)
    role = PlatformRole(
        code=body.code,
        name=body.name,
        description=body.description,
        is_system=False,
        permissions=perms,
    )
    db.add(role)
    await db.commit()
    loaded = await db.scalar(
        select(PlatformRole)
        .where(PlatformRole.id == role.id)
        .options(selectinload(PlatformRole.permissions))
    )
    return PlatformRoleRead.model_validate(loaded)


@router.patch("/platform-roles/{role_id}", response_model=PlatformRoleRead)
async def update_platform_role(
    role_id: int,
    body: PlatformRoleUpdate,
    _user: User = Depends(require_permissions("platform_role:write")),
    db: AsyncSession = Depends(get_db),
) -> PlatformRoleRead:
    role = await db.scalar(
        select(PlatformRole)
        .where(PlatformRole.id == role_id)
        .options(selectinload(PlatformRole.permissions))
    )
    if role is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Platform role not found",
        )
    if role.code == "super_admin" and body.permission_codes is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot modify permissions of system super_admin role",
        )
    if body.name is not None:
        role.name = body.name
    if body.description is not None:
        role.description = body.description
    if body.permission_codes is not None:
        role.permissions = await _load_permissions_by_codes(db, body.permission_codes)

    await db.commit()
    loaded = await db.scalar(
        select(PlatformRole)
        .where(PlatformRole.id == role.id)
        .options(selectinload(PlatformRole.permissions))
    )
    return PlatformRoleRead.model_validate(loaded)


@router.delete("/platform-roles/{role_id}", response_model=MessageResponse)
async def delete_platform_role(
    role_id: int,
    _user: User = Depends(require_permissions("platform_role:write")),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    role = await db.scalar(select(PlatformRole).where(PlatformRole.id == role_id))
    if role is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Platform role not found",
        )
    if role.is_system:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="System built-in platform roles cannot be deleted",
        )
    await db.delete(role)
    await db.commit()
    return MessageResponse(message="Platform role deleted")
