from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from fieldscope.api.deps import require_permissions
from fieldscope.db.models import ExternalPolicy, ExternalRole, Platform, PlatformEndpoint, User
from fieldscope.db.session import get_db
from fieldscope.schemas.common import MessageResponse
from fieldscope.schemas.external_rbac import (
    ExternalPolicyCreate,
    ExternalPolicyRead,
    ExternalPolicyUpdate,
    ExternalRoleCreate,
    ExternalRoleRead,
    ExternalRoleUpdate,
)

router = APIRouter(prefix="/api/v1/admin", tags=["external-rbac"])


async def _validate_platform_and_endpoint(
    db: AsyncSession,
    platform_id: int,
    endpoint_id: int | None,
) -> None:
    platform_exists = await db.scalar(select(Platform.id).where(Platform.id == platform_id))
    if platform_exists is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Platform {platform_id} not found",
        )
    if endpoint_id is not None:
        ep = await db.scalar(
            select(PlatformEndpoint).where(
                PlatformEndpoint.id == endpoint_id,
                PlatformEndpoint.platform_id == platform_id,
            )
        )
        if ep is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Endpoint {endpoint_id} does not belong to platform {platform_id}",
            )


@router.get("/external-roles", response_model=list[ExternalRoleRead])
async def list_external_roles(
    _admin: User = Depends(require_permissions("external_role:read")),
    db: AsyncSession = Depends(get_db),
) -> list[ExternalRoleRead]:
    rows = (
        await db.scalars(
            select(ExternalRole)
            .options(selectinload(ExternalRole.policies))
            .order_by(ExternalRole.id.asc())
        )
    ).all()
    return [ExternalRoleRead.model_validate(r) for r in rows]


@router.post(
    "/external-roles",
    response_model=ExternalRoleRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_external_role(
    body: ExternalRoleCreate,
    _admin: User = Depends(require_permissions("external_role:write")),
    db: AsyncSession = Depends(get_db),
) -> ExternalRoleRead:
    exists = await db.scalar(select(ExternalRole.id).where(ExternalRole.code == body.code))
    if exists is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"External role code '{body.code}' already exists",
        )
    role = ExternalRole(
        code=body.code,
        name=body.name,
        description=body.description,
        is_active=body.is_active,
    )
    db.add(role)
    await db.commit()
    loaded = await db.scalar(
        select(ExternalRole)
        .where(ExternalRole.id == role.id)
        .options(selectinload(ExternalRole.policies))
    )
    return ExternalRoleRead.model_validate(loaded)


@router.get("/external-roles/{role_id}", response_model=ExternalRoleRead)
async def get_external_role(
    role_id: int,
    _admin: User = Depends(require_permissions("external_role:read")),
    db: AsyncSession = Depends(get_db),
) -> ExternalRoleRead:
    role = await db.scalar(
        select(ExternalRole)
        .where(ExternalRole.id == role_id)
        .options(selectinload(ExternalRole.policies))
    )
    if role is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="External role not found",
        )
    return ExternalRoleRead.model_validate(role)


@router.patch("/external-roles/{role_id}", response_model=ExternalRoleRead)
async def update_external_role(
    role_id: int,
    body: ExternalRoleUpdate,
    _admin: User = Depends(require_permissions("external_role:write")),
    db: AsyncSession = Depends(get_db),
) -> ExternalRoleRead:
    role = await db.scalar(
        select(ExternalRole)
        .where(ExternalRole.id == role_id)
        .options(selectinload(ExternalRole.policies))
    )
    if role is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="External role not found",
        )
    if body.name is not None:
        role.name = body.name
    if body.description is not None:
        role.description = body.description
    if body.is_active is not None:
        role.is_active = body.is_active
    await db.commit()
    loaded = await db.scalar(
        select(ExternalRole)
        .where(ExternalRole.id == role.id)
        .options(selectinload(ExternalRole.policies))
    )
    return ExternalRoleRead.model_validate(loaded)


@router.delete("/external-roles/{role_id}", response_model=MessageResponse)
async def delete_external_role(
    role_id: int,
    _admin: User = Depends(require_permissions("external_role:write")),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    role = await db.scalar(select(ExternalRole).where(ExternalRole.id == role_id))
    if role is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="External role not found",
        )
    await db.delete(role)
    await db.commit()
    return MessageResponse(message="External role deleted")


# ---------------------------------------------------------------------------
# External Role 4-Layer Policies
# ---------------------------------------------------------------------------


@router.get("/external-roles/{role_id}/policies", response_model=list[ExternalPolicyRead])
async def list_external_policies(
    role_id: int,
    _admin: User = Depends(require_permissions("external_role:read")),
    db: AsyncSession = Depends(get_db),
) -> list[ExternalPolicyRead]:
    role_exists = await db.scalar(select(ExternalRole.id).where(ExternalRole.id == role_id))
    if role_exists is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="External role not found",
        )
    rows = (
        await db.scalars(
            select(ExternalPolicy)
            .where(ExternalPolicy.external_role_id == role_id)
            .order_by(ExternalPolicy.priority.desc(), ExternalPolicy.id.asc())
        )
    ).all()
    return [ExternalPolicyRead.model_validate(p) for p in rows]


@router.post(
    "/external-roles/{role_id}/policies",
    response_model=ExternalPolicyRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_external_policy(
    role_id: int,
    body: ExternalPolicyCreate,
    _admin: User = Depends(require_permissions("external_role:write")),
    db: AsyncSession = Depends(get_db),
) -> ExternalPolicyRead:
    role_exists = await db.scalar(select(ExternalRole.id).where(ExternalRole.id == role_id))
    if role_exists is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="External role not found",
        )
    await _validate_platform_and_endpoint(db, body.platform_id, body.endpoint_id)

    policy = ExternalPolicy(
        external_role_id=role_id,
        platform_id=body.platform_id,
        endpoint_id=body.endpoint_id,
        name=body.name,
        effect=body.effect,
        priority=body.priority,
        request_rules=body.request_rules.model_dump(by_alias=True),
        row_filter=body.row_filter.model_dump() if body.row_filter else None,
        field_rules=body.field_rules.model_dump() if body.field_rules else None,
        is_active=body.is_active,
    )
    db.add(policy)
    await db.commit()
    await db.refresh(policy)
    return ExternalPolicyRead.model_validate(policy)


@router.patch("/external-policies/{policy_id}", response_model=ExternalPolicyRead)
async def update_external_policy(
    policy_id: int,
    body: ExternalPolicyUpdate,
    _admin: User = Depends(require_permissions("external_role:write")),
    db: AsyncSession = Depends(get_db),
) -> ExternalPolicyRead:
    policy = await db.scalar(select(ExternalPolicy).where(ExternalPolicy.id == policy_id))
    if policy is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found")

    target_platform_id = body.platform_id if body.platform_id is not None else policy.platform_id
    target_endpoint_id = (
        body.endpoint_id
        if "endpoint_id" in body.model_fields_set
        else policy.endpoint_id
    )
    if body.platform_id is not None or "endpoint_id" in body.model_fields_set:
        await _validate_platform_and_endpoint(db, target_platform_id, target_endpoint_id)
        policy.platform_id = target_platform_id
        policy.endpoint_id = target_endpoint_id

    if body.name is not None:
        policy.name = body.name
    if body.effect is not None:
        policy.effect = body.effect
    if body.priority is not None:
        policy.priority = body.priority
    if body.request_rules is not None:
        policy.request_rules = body.request_rules.model_dump(by_alias=True)
    if "row_filter" in body.model_fields_set:
        policy.row_filter = body.row_filter.model_dump() if body.row_filter else None
    if "field_rules" in body.model_fields_set:
        policy.field_rules = body.field_rules.model_dump() if body.field_rules else None
    if body.is_active is not None:
        policy.is_active = body.is_active

    await db.commit()
    await db.refresh(policy)
    return ExternalPolicyRead.model_validate(policy)


@router.delete("/external-policies/{policy_id}", response_model=MessageResponse)
async def delete_external_policy(
    policy_id: int,
    _admin: User = Depends(require_permissions("external_role:write")),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    policy = await db.scalar(select(ExternalPolicy).where(ExternalPolicy.id == policy_id))
    if policy is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found")
    await db.delete(policy)
    await db.commit()
    return MessageResponse(message="Policy deleted")
