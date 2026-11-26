from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from fieldscope.db.models import ExternalPolicy, ExternalRole, User
from fieldscope.field_engine.engine import MergedFieldRules, normalize_field_path
from fieldscope.field_engine.transforms import TRANSFORM_STRICTNESS
from fieldscope.policy_engine.expr import UnsafeExpressionError, evaluate_expr
from fieldscope.policy_engine.template import render_policy_value


@dataclass
class ValidationRuleSpec:
    expr: str
    message: str


@dataclass
class RowFilterSpec:
    list_path: str
    expr: str


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str = ""
    matched_policy_ids: list[int] = field(default_factory=list)
    validations: list[ValidationRuleSpec] = field(default_factory=list)
    enforced_params: dict[str, Any] = field(default_factory=dict)
    row_filters: list[RowFilterSpec] = field(default_factory=list)
    row_filter_unrestricted: bool = False
    field_rules: MergedFieldRules = field(
        default_factory=lambda: MergedFieldRules(mode="none")
    )


@dataclass
class RowFilterResult:
    data: Any
    rows_before: int | None = None
    rows_after: int | None = None


def build_user_context(user: User) -> dict[str, Any]:
    return {
        "id": user.id,
        "username": user.username,
        "display_name": user.display_name,
        "email": user.email,
        "department": user.department,
        "attributes": dict(user.attributes or {}),
    }


def evaluate_policies_for_endpoint(
    user: User,
    policies: list[ExternalPolicy],
    platform_id: int,
    endpoint_id: int | None,
) -> PolicyDecision:
    """Evaluate all active external policies for a user against a target platform & endpoint.

    Merge semantics (security-first):
    - Default deny if no active allow policy matches.
    - Explicit deny overrides all allow policies.
    - Multiple allow policies union their allowed fields & row filters.
    - Any denylist fields are explicitly excluded from the final allowed fields.
    - Conflicting field transforms pick the strictest transform (redact > hash > mask_*).
    - Conflicting enforced parameters pick the highest priority policy.
    """
    matching = [
        p
        for p in policies
        if p.is_active
        and p.platform_id == platform_id
        and (p.endpoint_id is None or (endpoint_id is not None and p.endpoint_id == endpoint_id))
    ]
    if not matching:
        return PolicyDecision(
            allowed=False,
            reason="No external data role policy grants access to this resource",
        )

    # Sort highest priority first; endpoint-specific policies beat platform wildcards on tie
    matching.sort(
        key=lambda p: (p.priority, 1 if p.endpoint_id is not None else 0, -p.id),
        reverse=True,
    )

    deny_policies = [p for p in matching if p.effect == "deny"]
    if deny_policies:
        top_deny = deny_policies[0]
        return PolicyDecision(
            allowed=False,
            reason=f"Access explicitly denied by policy '{top_deny.name or top_deny.id}'",
            matched_policy_ids=[p.id for p in deny_policies],
        )

    allow_policies = [p for p in matching if p.effect == "allow"]
    if not allow_policies:
        return PolicyDecision(allowed=False, reason="No matching allow policy")

    user_ctx = {"user": build_user_context(user)}
    matched_ids = [p.id for p in allow_policies]

    # 1. Request validations & forced parameter injections
    validations: list[ValidationRuleSpec] = []
    seen_validations: set[str] = set()
    enforced_params: dict[str, Any] = {}

    for pol in allow_policies:
        req_rules = pol.request_rules or {}
        for item in req_rules.get("validate") or []:
            expr = str(item.get("expr", "")).strip()
            if expr and expr not in seen_validations:
                seen_validations.add(expr)
                validations.append(
                    ValidationRuleSpec(
                        expr=expr,
                        message=str(
                            item.get("message") or "Request parameter violates data scope policy"
                        ),
                    )
                )
        for param_key, raw_val in (req_rules.get("enforce") or {}).items():
            # Highest priority policy wins if multiple roles enforce the same parameter key
            if param_key not in enforced_params:
                enforced_params[param_key] = render_policy_value(raw_val, user_ctx)

    # 2. Post-response row filters (OR across allow roles; any unrestricted role lifts filter)
    row_filters: list[RowFilterSpec] = []
    row_filter_unrestricted = False
    for pol in allow_policies:
        rf = pol.row_filter
        if not rf or not rf.get("expr"):
            row_filter_unrestricted = True
        else:
            row_filters.append(
                RowFilterSpec(
                    list_path=str(rf.get("list_path") or "").strip(),
                    expr=str(rf["expr"]).strip(),
                )
            )

    # 3. Field-level merge (union allowlists, explicit denylist wins, strictest transform wins)
    has_unrestricted_fields = False
    allowlist_fields: list[str] = []
    denylist_fields: list[str] = []
    transforms: dict[str, str] = {}

    for pol in allow_policies:
        fr = pol.field_rules
        if not fr:
            has_unrestricted_fields = True
            continue
        mode = fr.get("mode", "allowlist")
        fields = [normalize_field_path(f) for f in (fr.get("fields") or []) if f]
        if mode == "allowlist":
            for f_path in fields:
                if f_path not in allowlist_fields:
                    allowlist_fields.append(f_path)
        elif mode == "denylist":
            has_unrestricted_fields = True
            for f_path in fields:
                if f_path not in denylist_fields:
                    denylist_fields.append(f_path)

        for tf in fr.get("transforms") or []:
            t_path = normalize_field_path(str(tf.get("path") or ""))
            t_action = str(tf.get("action") or "")
            if not t_path or not t_action:
                continue
            existing_action = transforms.get(t_path)
            if existing_action is None or TRANSFORM_STRICTNESS.get(
                t_action, 0
            ) > TRANSFORM_STRICTNESS.get(existing_action, 0):
                transforms[t_path] = t_action

    if has_unrestricted_fields:
        merged_field_rules = MergedFieldRules(
            mode="denylist" if denylist_fields else "none",
            fields=denylist_fields,
            denied_fields=[],
            transforms=transforms,
        )
    else:
        merged_field_rules = MergedFieldRules(
            mode="allowlist",
            fields=allowlist_fields,
            denied_fields=denylist_fields,
            transforms=transforms,
        )

    return PolicyDecision(
        allowed=True,
        matched_policy_ids=matched_ids,
        validations=validations,
        enforced_params=enforced_params,
        row_filters=row_filters,
        row_filter_unrestricted=row_filter_unrestricted,
        field_rules=merged_field_rules,
    )


async def load_user_external_policies(db: AsyncSession, user: User) -> list[ExternalPolicy]:
    """Load all active policies across all active external roles assigned to a user."""
    loaded_user = await db.scalar(
        select(User)
        .where(User.id == user.id)
        .options(
            selectinload(User.external_roles).selectinload(ExternalRole.policies),
        )
    )
    if loaded_user is None:
        return []
    policies: list[ExternalPolicy] = []
    for role in loaded_user.external_roles:
        if not role.is_active:
            continue
        for pol in role.policies:
            if pol.is_active:
                policies.append(pol)
    return policies


def validate_request_params(
    decision: PolicyDecision,
    *,
    user: User,
    query: dict[str, Any] | None = None,
    body: dict[str, Any] | None = None,
    path: dict[str, Any] | None = None,
    args: dict[str, Any] | None = None,
) -> tuple[bool, str | None]:
    """Validate incoming request parameters against all policy validation expressions."""
    context: dict[str, Any] = {
        "user": build_user_context(user),
        "query": query or {},
        "body": body or {},
        "path": path or {},
        "args": args or {},
    }
    for rule in decision.validations:
        try:
            passed = bool(evaluate_expr(rule.expr, context))
        except UnsafeExpressionError as exc:
            return False, f"Invalid policy validation expression: {exc}"
        if not passed:
            return False, rule.message
    return True, None


class GovernanceError(RuntimeError):
    """Raised when response or request governance cannot be safely applied (fail-closed)."""


def has_active_response_governance(decision: PolicyDecision) -> bool:
    """Return True if any row filtering, field pruning, or field masking applies."""
    has_row_filter = bool(decision.row_filters) and not decision.row_filter_unrestricted
    fr = decision.field_rules
    has_field_rules = (
        fr.mode in ("allowlist", "denylist")
        or bool(fr.denied_fields)
        or bool(fr.transforms)
    )
    return has_row_filter or has_field_rules


def apply_enforced_params_http(
    enforced: dict[str, Any],
    *,
    query: dict[str, Any],
    body: Any,
    path_params: dict[str, Any],
) -> tuple[dict[str, Any], Any, dict[str, Any]]:
    """Force-override HTTP query/body/path parameters from merged policy rules."""
    new_query = dict(query)
    new_body = copy.deepcopy(body)
    new_path = dict(path_params)

    for key, val in enforced.items():
        if key.startswith("query."):
            new_query[key[len("query.") :]] = val
        elif key.startswith("path."):
            new_path[key[len("path.") :]] = val
        elif key.startswith("body."):
            if new_body is None:
                new_body = {}
            if not isinstance(new_body, dict):
                raise GovernanceError(
                    f"Cannot enforce body parameter '{key}' on non-object request body"
                )
            _set_nested(new_body, key[len("body.") :], val)
    return new_query, new_body, new_path


def apply_enforced_params_mcp(
    enforced: dict[str, Any],
    arguments: dict[str, Any],
) -> dict[str, Any]:
    """Force-override MCP tool arguments (supporting args.*, query.*, body.*, path.* keys)."""
    new_args = copy.deepcopy(arguments)
    for key, val in enforced.items():
        for prefix in ("args.", "query.", "body.", "path."):
            if key.startswith(prefix):
                _set_nested(new_args, key[len(prefix) :], val)
                break
        else:
            _set_nested(new_args, key, val)
    return new_args


def _set_nested(target: dict[str, Any], dotted: str, value: Any) -> None:
    parts = [p for p in dotted.split(".") if p]
    if not parts:
        return
    curr = target
    for part in parts[:-1]:
        nxt = curr.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            curr[part] = nxt
        curr = nxt
    curr[parts[-1]] = value


def _get_nested_list_container(
    data: Any,
    list_path: str,
) -> tuple[Any, str | None, list[Any] | None]:
    clean = normalize_field_path(list_path)
    if not clean:
        return (None, None, data) if isinstance(data, list) else (None, None, None)

    parts = clean.split(".")
    curr = data
    for part in parts[:-1]:
        if isinstance(curr, dict) and part in curr:
            curr = curr[part]
        else:
            return None, None, None
    last = parts[-1]
    if isinstance(curr, dict) and isinstance(curr.get(last), list):
        return curr, last, curr[last]
    return None, None, None


def apply_row_filters(
    data: Any,
    decision: PolicyDecision,
    *,
    user: User,
) -> RowFilterResult:
    """Filter response JSON rows post-fetch using OR union across matched allow policies.

    Fail-closed: if a configured row_filter list_path is missing/not a list, or if an
    expression fails safety validation, raises GovernanceError rather than leaking data.
    """
    if decision.row_filter_unrestricted or not decision.row_filters:
        return RowFilterResult(data=data)

    working = copy.deepcopy(data)
    user_ctx = build_user_context(user)

    # Group filters by list_path (normally all policies for an endpoint target the same list_path)
    by_path: dict[str, list[str]] = {}
    for rf in decision.row_filters:
        norm_path = normalize_field_path(rf.list_path)
        by_path.setdefault(norm_path, []).append(rf.expr)

    total_before: int | None = None
    total_after: int | None = None

    for list_path, exprs in by_path.items():
        parent, key, target_list = _get_nested_list_container(working, list_path)
        if target_list is None:
            path_label = list_path or "<root>"
            raise GovernanceError(
                f"Row filter fail-closed: list_path '{path_label}' not found or not a JSON list"
            )

        kept: list[Any] = []
        for row in target_list:
            row_ctx = {"row": row, "user": user_ctx}
            matched_any = False
            for expr in exprs:
                try:
                    if bool(evaluate_expr(expr, row_ctx)):
                        matched_any = True
                        break
                except UnsafeExpressionError as exc:
                    raise GovernanceError(
                        f"Row filter fail-closed: invalid expression ({exc})"
                    ) from exc
            if matched_any:
                kept.append(row)

        total_before = (total_before or 0) + len(target_list)
        total_after = (total_after or 0) + len(kept)

        if parent is None and key is None:
            working = kept
        elif parent is not None and key is not None:
            parent[key] = kept

    return RowFilterResult(data=working, rows_before=total_before, rows_after=total_after)
