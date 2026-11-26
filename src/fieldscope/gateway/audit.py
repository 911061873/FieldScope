from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from fieldscope.api.deps import DataPlanePrincipal
from fieldscope.db.base import utc_now
from fieldscope.db.models import AuditLog


async def record_audit_log(
    db: AsyncSession,
    *,
    trace_id: str,
    principal: DataPlanePrincipal,
    protocol: str,
    platform_code: str,
    endpoint_code: str | None,
    decision: str,
    matched_policy_ids: list[int] | None = None,
    enforced_params: dict[str, Any] | None = None,
    rows_before: int | None = None,
    rows_after: int | None = None,
    pruned_fields: list[str] | None = None,
    transformed_fields: list[str] | None = None,
    upstream_status: int | None = None,
    latency_ms: int = 0,
    error_message: str | None = None,
) -> AuditLog:
    """Persist structured metadata-only audit trail (never stores raw sensitive response bodies)."""
    entry = AuditLog(
        trace_id=trace_id,
        user_id=principal.user.id,
        username=principal.user.username,
        app_id=principal.app.id if principal.app else None,
        app_code=principal.app.app_code if principal.app else None,
        protocol=protocol,
        platform_code=platform_code,
        endpoint_code=endpoint_code,
        decision=decision,
        matched_policy_ids=matched_policy_ids or [],
        enforced_params=enforced_params or {},
        rows_before=rows_before,
        rows_after=rows_after,
        pruned_fields=pruned_fields or [],
        transformed_fields=transformed_fields or [],
        upstream_status=upstream_status,
        latency_ms=latency_ms,
        error_message=error_message,
        created_at=utc_now(),
    )
    db.add(entry)
    await db.commit()
    return entry
