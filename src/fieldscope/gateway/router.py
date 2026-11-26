from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from fieldscope.api.deps import DataPlanePrincipal, resolve_data_plane_principal
from fieldscope.db.session import get_db
from fieldscope.gateway.pipeline import GatewayPipeline

router = APIRouter(tags=["data-plane"])


def get_gateway_pipeline(request: Request) -> GatewayPipeline:
    return request.app.state.gateway_pipeline


@router.api_route(
    "/gateway/{platform_code}/{sub_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
async def http_proxy_gateway(
    platform_code: str,
    sub_path: str,
    request: Request,
    principal: DataPlanePrincipal = Depends(resolve_data_plane_principal),
    db: AsyncSession = Depends(get_db),
    pipeline: GatewayPipeline = Depends(get_gateway_pipeline),
) -> Response:
    """Data-plane HTTP reverse proxy with per-user policy, auth renewal, row & field governance."""
    body: Any = None
    raw_body: bytes | None = None
    if request.method in ("POST", "PUT", "PATCH"):
        raw = await request.body()
        if raw:
            raw_body = raw
            try:
                body = await request.json()
            except ValueError:
                body = raw.decode("utf-8", errors="replace")

    result = await pipeline.execute_http_proxy(
        db,
        principal,
        platform_code=platform_code,
        method=request.method,
        sub_path=sub_path,
        query_params=dict(request.query_params),
        incoming_headers=dict(request.headers),
        body=body,
        raw_body=raw_body,
    )
    resp_headers = {**result.headers, "X-FieldScope-Trace-Id": result.trace_id}
    if result.is_json:
        return JSONResponse(
            content=result.body,
            status_code=result.status_code,
            headers=resp_headers,
        )
    return Response(
        content=result.body,
        status_code=result.status_code,
        media_type=result.content_type,
        headers=resp_headers,
    )


def _jsonrpc_ok(req_id: Any, result: Any) -> JSONResponse:
    return JSONResponse(content={"jsonrpc": "2.0", "id": req_id, "result": result})


def _jsonrpc_error(req_id: Any, code: int, message: str, http_status: int = 200) -> JSONResponse:
    return JSONResponse(
        status_code=http_status,
        content={
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": code, "message": message},
        },
    )


@router.get("/mcp")
async def mcp_streamable_http_get(
    _principal: DataPlanePrincipal = Depends(resolve_data_plane_principal),
) -> Response:
    """Server-initiated SSE stream is not offered; return 405 per MCP Streamable HTTP spec."""
    return Response(status_code=405, headers={"Allow": "POST, DELETE"})


@router.delete("/mcp")
async def mcp_streamable_http_delete(
    _principal: DataPlanePrincipal = Depends(resolve_data_plane_principal),
) -> Response:
    """Stateless session termination acknowledgement."""
    return Response(status_code=204)


@router.post("/mcp")
async def mcp_streamable_http_gateway(
    request: Request,
    principal: DataPlanePrincipal = Depends(resolve_data_plane_principal),
    db: AsyncSession = Depends(get_db),
    pipeline: GatewayPipeline = Depends(get_gateway_pipeline),
) -> Response:
    """MCP Streamable HTTP JSON-RPC 2.0 gateway (REST-to-MCP & upstream MCP proxy)."""
    try:
        payload = await request.json()
    except ValueError:
        return _jsonrpc_error(None, -32700, "Parse error: invalid JSON", http_status=400)

    if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0":
        return _jsonrpc_error(None, -32600, "Invalid Request: expected JSON-RPC 2.0 object")

    is_notification = "id" not in payload
    req_id = payload.get("id")
    method = payload.get("method")
    params = payload.get("params") or {}

    # JSON-RPC 2.0 notifications must not receive an error/result payload
    if is_notification or (isinstance(method, str) and method.startswith("notifications/")):
        return Response(status_code=202)

    if method == "initialize":
        return _jsonrpc_ok(
            req_id,
            {
                "protocolVersion": "2025-03-26",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "FieldScope", "version": "0.1.0"},
            },
        )

    if method == "ping":
        return _jsonrpc_ok(req_id, {})

    if method == "tools/list":
        tools = await pipeline.list_visible_mcp_tools(db, principal)
        return _jsonrpc_ok(req_id, {"tools": tools})

    if method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(tool_name, str) or not tool_name:
            return _jsonrpc_error(
                req_id, -32602, "Invalid params: 'name' must be a non-empty string"
            )
        if not isinstance(arguments, dict):
            return _jsonrpc_error(req_id, -32602, "Invalid params: 'arguments' must be an object")

        try:
            result = await pipeline.execute_mcp_tool(
                db,
                principal,
                tool_name=tool_name,
                arguments=arguments,
            )
            return _jsonrpc_ok(req_id, result)
        except PermissionError as exc:
            return _jsonrpc_error(req_id, -32003, str(exc))
        except RuntimeError as exc:
            return _jsonrpc_error(req_id, -32000, str(exc))

    return _jsonrpc_error(req_id, -32601, f"Method not found: {method}")
