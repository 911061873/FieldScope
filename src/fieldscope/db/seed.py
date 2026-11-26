from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from fieldscope.core.config import Settings
from fieldscope.core.permissions import BUILTIN_PERMISSIONS, BUILTIN_PLATFORM_ROLES
from fieldscope.core.security import hash_password
from fieldscope.db.models import PlatformPermission, PlatformRole, User


async def seed_initial_data(session: AsyncSession, settings: Settings) -> None:
    """Idempotently seed built-in permissions, system platform roles, and bootstrap admin."""
    # 1. Upsert built-in platform internal permissions
    existing_perms = {
        p.code: p
        for p in (await session.scalars(select(PlatformPermission))).all()
    }
    for spec in BUILTIN_PERMISSIONS:
        perm = existing_perms.get(spec.code)
        if perm is None:
            perm = PlatformPermission(
                code=spec.code,
                name=spec.name,
                module=spec.module,
                description=spec.description,
            )
            session.add(perm)
            existing_perms[spec.code] = perm
        else:
            perm.name = spec.name
            perm.module = spec.module
            perm.description = spec.description

    await session.flush()

    # 2. Seed built-in platform internal roles if missing
    existing_roles = {
        r.code: r
        for r in (
            await session.scalars(
                select(PlatformRole).options(selectinload(PlatformRole.permissions))
            )
        ).all()
    }
    for role_spec in BUILTIN_PLATFORM_ROLES:
        role = existing_roles.get(role_spec.code)
        if role is None:
            role = PlatformRole(
                code=role_spec.code,
                name=role_spec.name,
                description=role_spec.description,
                is_system=role_spec.is_system,
                permissions=[existing_perms[code] for code in role_spec.permissions],
            )
            session.add(role)
            existing_roles[role_spec.code] = role
        elif role_spec.code == "super_admin":
            # Keep super_admin aligned with all built-in permissions across upgrades.
            role.permissions = list(existing_perms.values())

    await session.flush()

    # 3. Bootstrap initial superuser only if no users exist yet
    user_count = await session.scalar(select(func.count(User.id)))
    if not user_count:
        admin_user = User(
            username=settings.bootstrap_admin_username,
            password_hash=hash_password(settings.bootstrap_admin_password),
            display_name=settings.bootstrap_admin_display_name,
            email="admin@fieldscope.local",
            department="Platform",
            attributes={},
            is_active=True,
            is_superuser=True,
            platform_roles=[existing_roles["super_admin"]],
        )
        session.add(admin_user)

    await session.commit()
