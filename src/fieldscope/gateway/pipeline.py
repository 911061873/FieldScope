from __future__ import annotations

import json
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, unquote

import httpx
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from fieldscope.api.deps import DataPlanePrincipal
from fieldscope.auth_engine.engine import AuthEngine, AuthEngineError, AuthInjection
from fieldscope.connectors.mcp_upstream import UpstreamMcpClient, UpstreamMcpError
from fieldscope.db.models import Platform, PlatformEndpoint
from fieldscope.field_engine.engine import apply_field_rules
from fieldscope.gateway.audit import record_audit_log
from fieldscope.policy_engine.engine import (
    GovernanceError,
    apply_enforced_params_http,
    apply_enforced_params_mcp,
    apply_row_filters,
    evaluate_policies_for_endpoint,
    has_active_response_governance,
    load_user_external_policies,
    validate_request_params,
)

_STRIPPED_REQUEST_HEADERS = frozenset(
    {
        "host",
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "content-length",
        "authorization",
        "cookie",
        "x-fieldscope-user",
    }
)

_STRIPPED_RESPONSE_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "content-length",
        "content-encoding",
        "content-type",
        "set-cookie",
    }
)

_PATH_PARAM_RE = re.compile(r"\{([a-zA-Z0-9_]+)\}|:([a-zA-Z0-9_]+)")


@dataclass
class GatewayHttpResult:
    status_code: int
    body: Any
    is_json: bool
    content_type: str
    trace_id: str
    headers: dict[str, str] = field(default_factory=dict)


def _normalize_path(path: str) -> str:
    stripped = path.strip()
    if not stripped.startswith("/"):
        stripped = "/" + stripped
    if len(stripped) > 1 and stripped.endswith("/"):
        stripped = stripped.rstrip("/")
    return stripped


def _has_unsafe_segment(segment: str) -> bool:
    """Reject traversal segments ('.', '..'), decoded slashes, query/fragment, or control chars."""
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in segment):
        return True
    decoded = unquote(segment)
    if decoded in (".", ".."):
        return True
    if any(ch in decoded for ch in ("/", "\\", "?", "#")):
        return True
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in decoded):
        return True
    return False


def _validate_actual_path(actual_path: str) -> str | None:
    if any(ch in actual_path for ch in ("?", "#", "\\")) or any(
        ord(ch) < 32 or ord(ch) == 127 for ch in actual_path
    ):
        return None
    norm = _normalize_path(actual_path)
    parts = norm.split("/")[1:] if norm != "/" else []
    for seg in parts:
        if not seg or _has_unsafe_segment(seg):
            return None
    return norm


def canonicalize_path_pattern(pattern: str) -> str:
    """Normalize parameter names in a pattern so colliding routes can be detected."""
    norm = _normalize_path(pattern)
    parts = norm.split("/")
    canon_parts = ["{}" if _PATH_PARAM_RE.fullmatch(p) else p for p in parts]
    return "/".join(canon_parts)


def pattern_specificity_key(pattern: str) -> tuple[tuple[int, ...], int, int]:
    """Rank route patterns so more specific routes always win over wildcards/params.

    Segment scores: literal (3) > {param} (2) > '*' (1) > '**' (0).
    """
    norm = _normalize_path(pattern)
    parts = norm.split("/")[1:] if norm != "/" else []
    ranks: list[int] = []
    has_glob = False
    for seg in parts:
        if seg == "**":
            ranks.append(0)
            has_glob = True
            break
        if seg == "*":
            ranks.append(1)
        elif _PATH_PARAM_RE.fullmatch(seg):
            ranks.append(2)
        else:
            ranks.append(3)
    return (tuple(ranks), 0 if has_glob else 1, len(ranks))


def match_path_pattern(pattern: str, actual_path: str) -> dict[str, str] | None:
    """Match '/api/v1/issue/{key}' or '/api/v1/issue/:key' or wildcards against an actual path."""
    norm_act = _validate_actual_path(actual_path)
    if norm_act is None:
        return None
    norm_pat = _normalize_path(pattern)

    pat_parts = norm_pat.split("/")
    act_parts = norm_act.split("/")

    if len(pat_parts) != len(act_parts) and "**" not in pat_parts:
        return None

    params: dict[str, str] = {}
    for idx, p_seg in enumerate(pat_parts):
        if p_seg == "**":
            return params
        if idx >= len(act_parts):
            return None
        a_seg = act_parts[idx]
        if p_seg == "*":
            continue
        m = _PATH_PARAM_RE.fullmatch(p_seg)
        if m:
            param_name = m.group(1) or m.group(2)
            params[param_name] = unquote(a_seg)
        elif p_seg != a_seg:
            return None

    return params if len(pat_parts) == len(act_parts) else None


def render_path_pattern(pattern: str, path_params: dict[str, Any]) -> str:
    """Safely substitute & percent-encode path parameters into a path pattern."""

    def _repl(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(2)
        if name not in path_params or path_params[name] is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Missing required path parameter '{name}'",
            )
        raw = str(path_params[name])
        if not raw or _has_unsafe_segment(raw):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid path parameter value for '{name}'",
            )
        return quote(raw, safe="")

    rendered = _normalize_path(_PATH_PARAM_RE.sub(_repl, pattern))
    if match_path_pattern(pattern, rendered) is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Rendered upstream path failed pattern verification",
        )
    return rendered


def _extract_path_param_names(pattern: str) -> set[str]:
    return {m.group(1) or m.group(2) for m in _PATH_PARAM_RE.finditer(pattern)}


def _sanitize_mcp_input_schema(schema: dict[str, Any] | None) -> dict[str, Any]:
    """Return a clean JSON Schema for MCP clients without internal x-in routing hints."""
    if not isinstance(schema, dict) or not schema:
        return {"type": "object", "properties": {}}
    cleaned = dict(schema)
    raw_props = schema.get("properties")
    if isinstance(raw_props, dict):
        clean_props: dict[str, Any] = {}
        for k, v in raw_props.items():
            if isinstance(v, dict):
                clean_props[k] = {pk: pv for pk, pv in v.items() if pk != "x-in"}
            else:
                clean_props[k] = v
        cleaned["properties"] = clean_props
    return cleaned


def _partition_rest_mcp_args(
    *,
    pattern: str,
    method: str,
    input_schema: dict[str, Any] | None,
    args: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, str], dict[str, Any]]:
    """Split REST-to-MCP arguments into (path, query, header, body) using schema x-in hints."""
    path_param_names = _extract_path_param_names(pattern)
    props = (
        input_schema.get("properties")
        if isinstance(input_schema, dict) and isinstance(input_schema.get("properties"), dict)
        else {}
    )

    path_params: dict[str, Any] = {}
    query_params: dict[str, Any] = {}
    header_params: dict[str, str] = {}
    body_params: dict[str, Any] = {}

    for key, val in args.items():
        prop_def = props.get(key) if isinstance(props, dict) else None
        hint = prop_def.get("x-in") if isinstance(prop_def, dict) else None

        if key in path_param_names or hint == "path":
            path_params[key] = val
        elif hint == "query":
            query_params[key] = val
        elif hint == "header":
            if key.lower() in _STRIPPED_REQUEST_HEADERS:
                continue
            str_val = str(val)
            if "\r" in str_val or "\n" in str_val:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid header parameter value for '{key}'",
                )
            header_params[key] = str_val
        elif hint == "body":
            body_params[key] = val
        elif method in ("GET", "DELETE"):
            query_params[key] = val
        else:
            body_params[key] = val

    return path_params, query_params, header_params, body_params


def _extract_safe_response_headers(response: httpx.Response) -> dict[str, str]:
    safe: dict[str, str] = {}
    for k, v in response.headers.items():
        if k.lower() in _STRIPPED_RESPONSE_HEADERS:
            continue
        safe[k] = v
    return safe


class GatewayPipeline:
    """Unified Data-Plane pipeline governing both HTTP Proxy and MCP Tool calls."""

    def __init__(
        self,
        auth_engine: AuthEngine,
        mcp_upstream: UpstreamMcpClient | None = None,
    ) -> None:
        self._auth_engine = auth_engine
        self._mcp_upstream = mcp_upstream or UpstreamMcpClient(auth_engine)

    async def execute_http_proxy(
        self,
        db: AsyncSession,
        principal: DataPlanePrincipal,
        *,
        platform_code: str,
        method: str,
        sub_path: str,
        query_params: dict[str, Any],
        incoming_headers: dict[str, str],
        body: Any,
        raw_body: bytes | None = None,
    ) -> GatewayHttpResult:
        trace_id = uuid.uuid4().hex
        started = time.perf_counter()
        upper_method = method.upper()
        validated_path = _validate_actual_path(sub_path)

        platform = await db.scalar(
            select(Platform)
            .where(Platform.code == platform_code, Platform.is_active.is_(True))
            .options(selectinload(Platform.endpoints))
        )
        if platform is None or platform.protocol_type != "api":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Active API platform '{platform_code}' not found",
            )

        if validated_path is None:
            latency_ms = int((time.perf_counter() - started) * 1000)
            await record_audit_log(
                db,
                trace_id=trace_id,
                principal=principal,
                protocol="http",
                platform_code=platform_code,
                endpoint_code=None,
                decision="deny",
                latency_ms=latency_ms,
                error_message="Rejected unsafe request path",
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Request path contains disallowed traversal or control characters",
            )
        norm_path = validated_path

        # Rank all matching endpoints by specificity: literal > {param} > * > **
        candidates: list[
            tuple[tuple[tuple[int, ...], int, int], int, PlatformEndpoint, dict[str, str]]
        ] = []
        for ep in platform.endpoints:
            if not ep.is_active or ep.resource_type != "http_endpoint":
                continue
            if ep.method and ep.method.upper() != upper_method:
                continue
            if not ep.path_pattern:
                continue
            m = match_path_pattern(ep.path_pattern, norm_path)
            if m is not None:
                candidates.append((pattern_specificity_key(ep.path_pattern), -ep.id, ep, dict(m)))

        matched_endpoint: PlatformEndpoint | None = None
        path_params: dict[str, Any] = {}
        if candidates:
            candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
            _, _, matched_endpoint, path_params = candidates[0]

        if matched_endpoint is None:
            latency_ms = int((time.perf_counter() - started) * 1000)
            await record_audit_log(
                db,
                trace_id=trace_id,
                principal=principal,
                protocol="http",
                platform_code=platform_code,
                endpoint_code=None,
                decision="deny",
                latency_ms=latency_ms,
                error_message=f"Unregistered endpoint: {upper_method} {norm_path}",
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=(
                    f"Endpoint '{upper_method} {norm_path}' is not registered on '{platform_code}'"
                ),
            )

        policies = await load_user_external_policies(db, principal.user)
        decision = evaluate_policies_for_endpoint(
            principal.user,
            policies,
            platform_id=platform.id,
            endpoint_id=matched_endpoint.id,
        )
        if not decision.allowed:
            latency_ms = int((time.perf_counter() - started) * 1000)
            await record_audit_log(
                db,
                trace_id=trace_id,
                principal=principal,
                protocol="http",
                platform_code=platform_code,
                endpoint_code=matched_endpoint.code,
                decision="deny",
                matched_policy_ids=decision.matched_policy_ids,
                latency_ms=latency_ms,
                error_message=decision.reason,
            )
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

        # Pre-request validation
        valid, err_msg = validate_request_params(
            decision,
            user=principal.user,
            query=query_params,
            body=body if isinstance(body, dict) else {},
            path=path_params,
        )
        if not valid:
            latency_ms = int((time.perf_counter() - started) * 1000)
            await record_audit_log(
                db,
                trace_id=trace_id,
                principal=principal,
                protocol="http",
                platform_code=platform_code,
                endpoint_code=matched_endpoint.code,
                decision="deny",
                matched_policy_ids=decision.matched_policy_ids,
                latency_ms=latency_ms,
                error_message=err_msg,
            )
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=err_msg)

        # Forced parameter injection & safe path rendering (audited on failure)
        try:
            enforced_query, enforced_body, enforced_path_params = apply_enforced_params_http(
                decision.enforced_params,
                query=query_params,
                body=body,
                path_params=path_params,
            )
            final_path = (
                render_path_pattern(matched_endpoint.path_pattern, enforced_path_params)
                if enforced_path_params != path_params and matched_endpoint.path_pattern
                else norm_path
            )
        except GovernanceError as exc:
            latency_ms = int((time.perf_counter() - started) * 1000)
            await record_audit_log(
                db,
                trace_id=trace_id,
                principal=principal,
                protocol="http",
                platform_code=platform_code,
                endpoint_code=matched_endpoint.code,
                decision="deny",
                matched_policy_ids=decision.matched_policy_ids,
                enforced_params=decision.enforced_params,
                latency_ms=latency_ms,
                error_message=str(exc),
            )
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except HTTPException as exc:
            latency_ms = int((time.perf_counter() - started) * 1000)
            await record_audit_log(
                db,
                trace_id=trace_id,
                principal=principal,
                protocol="http",
                platform_code=platform_code,
                endpoint_code=matched_endpoint.code,
                decision="deny",
                matched_policy_ids=decision.matched_policy_ids,
                enforced_params=decision.enforced_params,
                latency_ms=latency_ms,
                error_message=str(exc.detail),
            )
            raise

        target_url = f"{platform.base_url}{final_path}"

        blocked_headers = set(_STRIPPED_REQUEST_HEADERS)
        if principal.app is not None and principal.app.user_identity_header:
            blocked_headers.add(principal.app.user_identity_header.lower())
        safe_fwd_headers = {
            k: v
            for k, v in incoming_headers.items()
            if k.lower() not in blocked_headers
        }

        send_json: Any = None
        send_raw: bytes | None = None
        if upper_method in ("POST", "PUT", "PATCH"):
            if isinstance(enforced_body, (dict, list)):
                send_json = enforced_body
            elif raw_body is not None:
                send_raw = raw_body
            elif enforced_body is not None:
                send_raw = str(enforced_body).encode("utf-8")

        async def _send(injection: AuthInjection) -> httpx.Response:
            req_headers = {**safe_fwd_headers, **platform.extra_headers, **injection.headers}
            req_query = {**enforced_query, **injection.query_params}
            return await self._auth_engine.send_http_request(
                upper_method,
                target_url,
                timeout_ms=platform.timeout_ms,
                headers=req_headers,
                params=req_query or None,
                json_body=send_json,
                content=send_raw,
            )

        try:
            upstream_resp, _retried = await self._auth_engine.execute_http_with_auth_retry(
                db,
                platform,
                _send,
            )
        except (AuthEngineError, httpx.HTTPError) as exc:
            latency_ms = int((time.perf_counter() - started) * 1000)
            await record_audit_log(
                db,
                trace_id=trace_id,
                principal=principal,
                protocol="http",
                platform_code=platform_code,
                endpoint_code=matched_endpoint.code,
                decision="error",
                matched_policy_ids=decision.matched_policy_ids,
                enforced_params=decision.enforced_params,
                latency_ms=latency_ms,
                error_message=str(exc),
            )
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc

        # Post-response row filtering & field pruning/masking (fail-closed when governance active)
        rows_before: int | None = None
        rows_after: int | None = None
        pruned_fields: list[str] = []
        transformed_fields: list[str] = []
        needs_governance = has_active_response_governance(decision)

        resp_ct = upstream_resp.headers.get("content-type", "application/json")
        resp_headers = _extract_safe_response_headers(upstream_resp)
        try:
            parsed_json = upstream_resp.json()
            is_json = True
        except ValueError:
            parsed_json = None
            is_json = False

        final_body: Any
        try:
            if needs_governance:
                if 200 <= upstream_resp.status_code < 300:
                    if not is_json:
                        raise GovernanceError(
                            "Response governance fail-closed: upstream returned non-JSON payload"
                        )
                    row_res = apply_row_filters(parsed_json, decision, user=principal.user)
                    rows_before = row_res.rows_before
                    rows_after = row_res.rows_after
                    field_res = apply_field_rules(row_res.data, decision.field_rules)
                    pruned_fields = field_res.pruned_fields
                    transformed_fields = field_res.transformed_fields
                    final_body = field_res.data
                else:
                    # Do not expose ungoverned upstream error bodies when data governance is active
                    is_json = True
                    resp_ct = "application/json"
                    final_body = {
                        "error": "Upstream request failed",
                        "upstream_status": upstream_resp.status_code,
                    }
            elif is_json:
                final_body = parsed_json
            else:
                final_body = upstream_resp.content
        except GovernanceError as exc:
            latency_ms = int((time.perf_counter() - started) * 1000)
            await record_audit_log(
                db,
                trace_id=trace_id,
                principal=principal,
                protocol="http",
                platform_code=platform_code,
                endpoint_code=matched_endpoint.code,
                decision="error",
                matched_policy_ids=decision.matched_policy_ids,
                enforced_params=decision.enforced_params,
                upstream_status=upstream_resp.status_code,
                latency_ms=latency_ms,
                error_message=str(exc),
            )
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=str(exc),
            ) from exc

        latency_ms = int((time.perf_counter() - started) * 1000)
        await record_audit_log(
            db,
            trace_id=trace_id,
            principal=principal,
            protocol="http",
            platform_code=platform_code,
            endpoint_code=matched_endpoint.code,
            decision="allow",
            matched_policy_ids=decision.matched_policy_ids,
            enforced_params=decision.enforced_params,
            rows_before=rows_before,
            rows_after=rows_after,
            pruned_fields=pruned_fields,
            transformed_fields=transformed_fields,
            upstream_status=upstream_resp.status_code,
            latency_ms=latency_ms,
        )

        return GatewayHttpResult(
            status_code=upstream_resp.status_code,
            body=final_body,
            is_json=is_json,
            content_type=resp_ct,
            trace_id=trace_id,
            headers=resp_headers,
        )

    # -----------------------------------------------------------------------
    # MCP Data-Plane Operations (Permission-Aware tools/list & tools/call)
    # -----------------------------------------------------------------------

    async def list_visible_mcp_tools(
        self,
        db: AsyncSession,
        principal: DataPlanePrincipal,
    ) -> list[dict[str, Any]]:
        """Return only MCP tools that the user's external roles are permitted to call."""
        policies = await load_user_external_policies(db, principal.user)
        if not policies:
            return []

        platforms = (
            await db.scalars(
                select(Platform)
                .where(Platform.is_active.is_(True))
                .options(selectinload(Platform.endpoints))
                .order_by(Platform.id.asc())
            )
        ).all()

        visible_tools: list[dict[str, Any]] = []
        for platform in platforms:
            for ep in platform.endpoints:
                if not ep.is_active:
                    continue
                if ep.resource_type == "http_endpoint" and not ep.expose_as_mcp:
                    continue
                decision = evaluate_policies_for_endpoint(
                    principal.user,
                    policies,
                    platform_id=platform.id,
                    endpoint_id=ep.id,
                )
                if not decision.allowed:
                    continue
                tool_name = ep.mcp_tool_name or f"{platform.code}_{ep.code}"
                schema = _sanitize_mcp_input_schema(ep.input_schema)
                visible_tools.append(
                    {
                        "name": tool_name,
                        "description": ep.description or f"{platform.name}: {ep.name}",
                        "inputSchema": schema,
                    }
                )
        return visible_tools

    async def execute_mcp_tool(
        self,
        db: AsyncSession,
        principal: DataPlanePrincipal,
        *,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        """Execute an MCP tool call (either REST-to-MCP or upstream MCP proxy) with governance."""
        trace_id = uuid.uuid4().hex
        started = time.perf_counter()

        # Locate target endpoint by mcp_tool_name across active platforms
        endpoints = (
            await db.scalars(
                select(PlatformEndpoint)
                .join(Platform, PlatformEndpoint.platform_id == Platform.id)
                .where(
                    Platform.is_active.is_(True),
                    PlatformEndpoint.is_active.is_(True),
                )
                .options(selectinload(PlatformEndpoint.platform))
                .order_by(PlatformEndpoint.id.asc())
            )
        ).all()

        target_ep: PlatformEndpoint | None = None
        for ep in endpoints:
            if ep.resource_type == "http_endpoint" and not ep.expose_as_mcp:
                continue
            effective_name = ep.mcp_tool_name or f"{ep.platform.code}_{ep.code}"
            if effective_name == tool_name:
                target_ep = ep
                break

        if target_ep is None:
            latency_ms = int((time.perf_counter() - started) * 1000)
            await record_audit_log(
                db,
                trace_id=trace_id,
                principal=principal,
                protocol="mcp",
                platform_code="unknown",
                endpoint_code=tool_name,
                decision="deny",
                latency_ms=latency_ms,
                error_message=f"Unknown MCP tool '{tool_name}'",
            )
            raise PermissionError(f"Tool '{tool_name}' not found or not available")

        platform = target_ep.platform
        policies = await load_user_external_policies(db, principal.user)
        decision = evaluate_policies_for_endpoint(
            principal.user,
            policies,
            platform_id=platform.id,
            endpoint_id=target_ep.id,
        )
        if not decision.allowed:
            latency_ms = int((time.perf_counter() - started) * 1000)
            await record_audit_log(
                db,
                trace_id=trace_id,
                principal=principal,
                protocol="mcp",
                platform_code=platform.code,
                endpoint_code=target_ep.code,
                decision="deny",
                matched_policy_ids=decision.matched_policy_ids,
                latency_ms=latency_ms,
                error_message=decision.reason,
            )
            raise PermissionError(decision.reason)

        # Validate MCP arguments (expose under args, query, and body for rule portability)
        valid, err_msg = validate_request_params(
            decision,
            user=principal.user,
            query=arguments,
            body=arguments,
            args=arguments,
        )
        if not valid:
            latency_ms = int((time.perf_counter() - started) * 1000)
            await record_audit_log(
                db,
                trace_id=trace_id,
                principal=principal,
                protocol="mcp",
                platform_code=platform.code,
                endpoint_code=target_ep.code,
                decision="deny",
                matched_policy_ids=decision.matched_policy_ids,
                latency_ms=latency_ms,
                error_message=err_msg,
            )
            raise PermissionError(err_msg or "Arguments violate policy")

        enforced_args = apply_enforced_params_mcp(decision.enforced_params, arguments)
        needs_governance = has_active_response_governance(decision)

        rows_before: int | None = None
        rows_after: int | None = None
        pruned_fields: list[str] = []
        transformed_fields: list[str] = []
        upstream_status: int | None = 200

        try:
            if target_ep.resource_type == "mcp_tool":
                raw_mcp_result = await self._mcp_upstream.call_tool(
                    db,
                    platform,
                    target_ep.code,
                    enforced_args,
                )
                processed_result, rows_before, rows_after, pruned_fields, transformed_fields = (
                    self._govern_mcp_result(raw_mcp_result, decision, principal)
                )
            else:
                # REST-to-MCP execution (supports path / query / header / body routing via x-in)
                method = (target_ep.method or "GET").upper()
                pattern = target_ep.path_pattern or "/"
                path_params, mcp_query, mcp_headers, mcp_body = _partition_rest_mcp_args(
                    pattern=pattern,
                    method=method,
                    input_schema=target_ep.input_schema,
                    args=enforced_args,
                )
                rendered_path = render_path_pattern(pattern, path_params)
                target_url = f"{platform.base_url}{rendered_path}"

                async def _send(injection: AuthInjection) -> httpx.Response:
                    req_headers = {**mcp_headers, **platform.extra_headers, **injection.headers}
                    req_query = {**mcp_query, **injection.query_params}
                    req_body = (
                        mcp_body
                        if (mcp_body or method not in ("GET", "DELETE"))
                        else None
                    )
                    return await self._auth_engine.send_http_request(
                        method,
                        target_url,
                        timeout_ms=platform.timeout_ms,
                        headers=req_headers,
                        params=req_query or None,
                        json_body=req_body,
                    )

                resp, _retried = await self._auth_engine.execute_http_with_auth_retry(
                    db,
                    platform,
                    _send,
                )
                upstream_status = resp.status_code
                try:
                    raw_data = resp.json()
                    is_json = True
                except ValueError:
                    raw_data = None
                    is_json = False

                if needs_governance:
                    if 200 <= resp.status_code < 300:
                        if not is_json:
                            raise GovernanceError(
                                "Response governance fail-closed: upstream returned non-JSON"
                            )
                        row_res = apply_row_filters(raw_data, decision, user=principal.user)
                        rows_before = row_res.rows_before
                        rows_after = row_res.rows_after
                        field_res = apply_field_rules(row_res.data, decision.field_rules)
                        pruned_fields = field_res.pruned_fields
                        transformed_fields = field_res.transformed_fields
                        text_out = json.dumps(field_res.data, ensure_ascii=False)
                    else:
                        text_out = json.dumps(
                            {
                                "error": "Upstream request failed",
                                "upstream_status": resp.status_code,
                            },
                            ensure_ascii=False,
                        )
                elif is_json:
                    text_out = json.dumps(raw_data, ensure_ascii=False)
                else:
                    text_out = resp.text

                processed_result = {
                    "content": [{"type": "text", "text": text_out}],
                    "isError": resp.status_code >= 400,
                }
        except (
            AuthEngineError,
            UpstreamMcpError,
            GovernanceError,
            httpx.HTTPError,
            HTTPException,
        ) as exc:
            err_detail = exc.detail if isinstance(exc, HTTPException) else str(exc)
            latency_ms = int((time.perf_counter() - started) * 1000)
            await record_audit_log(
                db,
                trace_id=trace_id,
                principal=principal,
                protocol="mcp",
                platform_code=platform.code,
                endpoint_code=target_ep.code,
                decision="error",
                matched_policy_ids=decision.matched_policy_ids,
                enforced_params=decision.enforced_params,
                upstream_status=upstream_status,
                latency_ms=latency_ms,
                error_message=str(err_detail),
            )
            raise RuntimeError(str(err_detail)) from exc

        latency_ms = int((time.perf_counter() - started) * 1000)
        await record_audit_log(
            db,
            trace_id=trace_id,
            principal=principal,
            protocol="mcp",
            platform_code=platform.code,
            endpoint_code=target_ep.code,
            decision="allow",
            matched_policy_ids=decision.matched_policy_ids,
            enforced_params=decision.enforced_params,
            rows_before=rows_before,
            rows_after=rows_after,
            pruned_fields=pruned_fields,
            transformed_fields=transformed_fields,
            upstream_status=upstream_status,
            latency_ms=latency_ms,
        )
        return processed_result

    def _govern_mcp_result(
        self,
        raw_result: dict[str, Any],
        decision: Any,
        principal: DataPlanePrincipal,
    ) -> tuple[dict[str, Any], int | None, int | None, list[str], list[str]]:
        """Apply row_filter & field_rules to structured or JSON-text MCP tool call results."""
        result = dict(raw_result)
        needs_governance = has_active_response_governance(decision)
        rows_before: int | None = None
        rows_after: int | None = None
        pruned_all: set[str] = set()
        transformed_all: set[str] = set()
        governed_any = False

        def _process_obj(obj: Any) -> Any:
            nonlocal rows_before, rows_after, governed_any
            row_res = apply_row_filters(obj, decision, user=principal.user)
            if row_res.rows_before is not None:
                rows_before = (rows_before or 0) + row_res.rows_before
                rows_after = (rows_after or 0) + (row_res.rows_after or 0)
            field_res = apply_field_rules(row_res.data, decision.field_rules)
            pruned_all.update(field_res.pruned_fields)
            transformed_all.update(field_res.transformed_fields)
            governed_any = True
            return field_res.data

        if "structuredContent" in result and result["structuredContent"] is not None:
            result["structuredContent"] = _process_obj(result["structuredContent"])

        content = result.get("content")
        if isinstance(content, list):
            new_content: list[Any] = []
            for block in content:
                if (
                    isinstance(block, dict)
                    and block.get("type") == "text"
                    and isinstance(block.get("text"), str)
                ):
                    try:
                        parsed = json.loads(block["text"])
                    except ValueError:
                        if needs_governance:
                            raise GovernanceError(
                                "MCP governance fail-closed: upstream text block is not valid JSON"
                            ) from None
                        new_content.append(block)
                        continue
                    governed = _process_obj(parsed)
                    new_block = dict(block)
                    new_block["text"] = json.dumps(governed, ensure_ascii=False)
                    new_content.append(new_block)
                    continue
                if needs_governance:
                    raise GovernanceError(
                        "MCP governance fail-closed: upstream returned non-JSON content block"
                    )
                new_content.append(block)
            result["content"] = new_content

        if needs_governance and not governed_any:
            raise GovernanceError(
                "MCP governance fail-closed: upstream tool returned no governable JSON payload"
            )

        return result, rows_before, rows_after, sorted(pruned_all), sorted(transformed_all)
