from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from fieldscope.api.deps import require_permissions
from fieldscope.db.models import AuditLog, User
from fieldscope.db.session import get_db

router = APIRouter(prefix="/api/v1/admin/audit-logs", tags=["audit"])


class AuditLogRead(BaseModel):
    id: int
    trace_id: str
    user_id: int | None
    username: str | None
    app_id: int | None
    app_code: str | None
    protocol: str
    platform_code: str
    endpoint_code: str | None
    decision: str
    matched_policy_ids: list[int]
    enforced_params: dict[str, Any]
    rows_before: int | None
    rows_after: int | None
    pruned_fields: list[str]
    transformed_fields: list[str]
    upstream_status: int | None
    latency_ms: int
    error_message: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class AuditLogPage(BaseModel):
    total: int
    items: list[AuditLogRead]


class AuditStatsRead(BaseModel):
    total: int
    allowed: int
    denied: int
    errors: int
    http_calls: int
    mcp_calls: int


@router.get("", response_model=AuditLogPage)
async def list_audit_logs(
    username: str | None = Query(default=None),
    platform_code: str | None = Query(default=None),
    protocol: str | None = Query(default=None),
    decision: str | None = Query(default=None),
    trace_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _admin: User = Depends(require_permissions("audit:read")),
    db: AsyncSession = Depends(get_db),
) -> AuditLogPage:
    stmt = select(AuditLog)
    count_stmt = select(func.count(AuditLog.id))

    if username:
        stmt = stmt.where(AuditLog.username == username)
        count_stmt = count_stmt.where(AuditLog.username == username)
    if platform_code:
        stmt = stmt.where(AuditLog.platform_code == platform_code)
        count_stmt = count_stmt.where(AuditLog.platform_code == platform_code)
    if protocol:
        stmt = stmt.where(AuditLog.protocol == protocol)
        count_stmt = count_stmt.where(AuditLog.protocol == protocol)
    if decision:
        stmt = stmt.where(AuditLog.decision == decision)
        count_stmt = count_stmt.where(AuditLog.decision == decision)
    if trace_id:
        stmt = stmt.where(AuditLog.trace_id == trace_id)
        count_stmt = count_stmt.where(AuditLog.trace_id == trace_id)

    total = int(await db.scalar(count_stmt) or 0)
    rows = (
        await db.scalars(stmt.order_by(AuditLog.id.desc()).offset(offset).limit(limit))
    ).all()
    return AuditLogPage(
        total=total,
        items=[AuditLogRead.model_validate(r) for r in rows],
    )


@router.get("/stats", response_model=AuditStatsRead)
async def get_audit_stats(
    _admin: User = Depends(require_permissions("audit:read")),
    db: AsyncSession = Depends(get_db),
) -> AuditStatsRead:
    total = int(await db.scalar(select(func.count(AuditLog.id))) or 0)
    allowed = int(
        await db.scalar(select(func.count(AuditLog.id)).where(AuditLog.decision == "allow")) or 0
    )
    denied = int(
        await db.scalar(select(func.count(AuditLog.id)).where(AuditLog.decision == "deny")) or 0
    )
    errors = int(
        await db.scalar(select(func.count(AuditLog.id)).where(AuditLog.decision == "error")) or 0
    )
    http_calls = int(
        await db.scalar(select(func.count(AuditLog.id)).where(AuditLog.protocol == "http")) or 0
    )
    mcp_calls = int(
        await db.scalar(select(func.count(AuditLog.id)).where(AuditLog.protocol == "mcp")) or 0
    )
    return AuditStatsRead(
        total=total,
        allowed=allowed,
        denied=denied,
        errors=errors,
        http_calls=http_calls,
        mcp_calls=mcp_calls,
    )
