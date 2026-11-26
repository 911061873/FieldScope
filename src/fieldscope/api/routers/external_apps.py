from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fieldscope.api.deps import require_permissions
from fieldscope.core.security import APP_API_KEY_PREFIX, generate_api_key
from fieldscope.db.models import ExternalApp, User
from fieldscope.db.session import get_db
from fieldscope.schemas.common import MessageResponse
from fieldscope.schemas.iam import (
    ExternalAppCreate,
    ExternalAppCreated,
    ExternalAppRead,
    ExternalAppUpdate,
)

router = APIRouter(prefix="/api/v1/admin/external-apps", tags=["external-apps"])


@router.get("", response_model=list[ExternalAppRead])
async def list_external_apps(
    _admin: User = Depends(require_permissions("external_app:read")),
    db: AsyncSession = Depends(get_db),
) -> list[ExternalAppRead]:
    rows = (await db.scalars(select(ExternalApp).order_by(ExternalApp.id.asc()))).all()
    return [ExternalAppRead.model_validate(a) for a in rows]


@router.post("", response_model=ExternalAppCreated, status_code=status.HTTP_201_CREATED)
async def create_external_app(
    body: ExternalAppCreate,
    _admin: User = Depends(require_permissions("external_app:write")),
    db: AsyncSession = Depends(get_db),
) -> ExternalAppCreated:
    exists = await db.scalar(select(ExternalApp.id).where(ExternalApp.app_code == body.app_code))
    if exists is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"External app code '{body.app_code}' already exists",
        )

    plain_key, key_prefix, key_hash = generate_api_key(APP_API_KEY_PREFIX)
    app = ExternalApp(
        app_code=body.app_code,
        name=body.name,
        description=body.description,
        key_prefix=key_prefix,
        key_hash=key_hash,
        user_identity_header=body.user_identity_header,
        allowed_user_ids=list(dict.fromkeys(body.allowed_user_ids)),
        allowed_external_role_ids=list(dict.fromkeys(body.allowed_external_role_ids)),
        is_active=body.is_active,
    )
    db.add(app)
    await db.commit()
    await db.refresh(app)
    return ExternalAppCreated(
        **ExternalAppRead.model_validate(app).model_dump(),
        plain_key=plain_key,
    )


@router.patch("/{app_id}", response_model=ExternalAppRead)
async def update_external_app(
    app_id: int,
    body: ExternalAppUpdate,
    _admin: User = Depends(require_permissions("external_app:write")),
    db: AsyncSession = Depends(get_db),
) -> ExternalAppRead:
    app = await db.scalar(select(ExternalApp).where(ExternalApp.id == app_id))
    if app is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="External app not found")
    if body.name is not None:
        app.name = body.name
    if body.description is not None:
        app.description = body.description
    if body.user_identity_header is not None:
        app.user_identity_header = body.user_identity_header
    if body.allowed_user_ids is not None:
        app.allowed_user_ids = list(dict.fromkeys(body.allowed_user_ids))
    if body.allowed_external_role_ids is not None:
        app.allowed_external_role_ids = list(dict.fromkeys(body.allowed_external_role_ids))
    if body.is_active is not None:
        app.is_active = body.is_active
    await db.commit()
    await db.refresh(app)
    return ExternalAppRead.model_validate(app)


@router.post("/{app_id}/rotate-key", response_model=ExternalAppCreated)
async def rotate_external_app_key(
    app_id: int,
    _admin: User = Depends(require_permissions("external_app:write")),
    db: AsyncSession = Depends(get_db),
) -> ExternalAppCreated:
    app = await db.scalar(select(ExternalApp).where(ExternalApp.id == app_id))
    if app is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="External app not found")
    plain_key, key_prefix, key_hash = generate_api_key(APP_API_KEY_PREFIX)
    app.key_prefix = key_prefix
    app.key_hash = key_hash
    await db.commit()
    await db.refresh(app)
    return ExternalAppCreated(
        **ExternalAppRead.model_validate(app).model_dump(),
        plain_key=plain_key,
    )


@router.delete("/{app_id}", response_model=MessageResponse)
async def delete_external_app(
    app_id: int,
    _admin: User = Depends(require_permissions("external_app:write")),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    app = await db.scalar(select(ExternalApp).where(ExternalApp.id == app_id))
    if app is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="External app not found")
    await db.delete(app)
    await db.commit()
    return MessageResponse(message="External app deleted")
