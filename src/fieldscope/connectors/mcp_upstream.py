from __future__ import annotations

import json
import uuid
from typing import Any
from urllib.parse import urljoin

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from fieldscope.auth_engine.engine import AuthEngine, AuthInjection
from fieldscope.db.models import Platform


class UpstreamMcpError(RuntimeError):
    """Raised when communicating with an upstream remote MCP server fails."""


def _parse_mcp_http_response(response: httpx.Response) -> dict[str, Any]:
    """Parse either application/json or text/event-stream JSON-RPC 2.0 response."""
    content_type = response.headers.get("content-type", "").lower()
    if "text/event-stream" in content_type:
        last_payload: dict[str, Any] | None = None
        for line in response.text.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                raw = line[5:].strip()
                if not raw:
                    continue
                try:
                    parsed = json.loads(raw)
                    if isinstance(parsed, dict) and ("result" in parsed or "error" in parsed):
                        last_payload = parsed
                except ValueError:
                    continue
        if last_payload is None:
            raise UpstreamMcpError("Upstream MCP SSE response contained no valid JSON-RPC message")
        return last_payload

    try:
        data = response.json()
    except ValueError as exc:
        raise UpstreamMcpError(
            f"Upstream MCP server returned non-JSON body (HTTP {response.status_code})"
        ) from exc
    if not isinstance(data, dict):
        raise UpstreamMcpError("Upstream MCP JSON-RPC response must be an object")
    return data


class UpstreamMcpClient:
    """Remote MCP client (Streamable HTTP & SSE) reusing FieldScope's AuthEngine."""

    def __init__(self, auth_engine: AuthEngine) -> None:
        self._auth_engine = auth_engine

    async def _resolve_rpc_url(
        self,
        platform: Platform,
        injection: AuthInjection,
    ) -> str:
        """For SSE transport, discover the message endpoint; for Streamable HTTP, use base_url."""
        if platform.mcp_transport != "sse":
            return platform.base_url

        headers = {
            "Accept": "text/event-stream",
            **platform.extra_headers,
            **injection.headers,
        }
        resp = await self._auth_engine._http_request(
            "GET",
            platform.base_url,
            timeout_ms=platform.timeout_ms,
            headers=headers,
            params=injection.query_params or None,
        )
        if resp.status_code >= 400:
            raise UpstreamMcpError(
                f"Upstream MCP SSE handshake failed with HTTP {resp.status_code}: {resp.text[:200]}"
            )
        # Standard MCP SSE emits: `event: endpoint\ndata: /messages?session_id=...`
        event_name = ""
        for line in resp.text.splitlines():
            stripped = line.strip()
            if stripped.startswith("event:"):
                event_name = stripped[6:].strip()
            elif stripped.startswith("data:") and event_name in ("endpoint", ""):
                endpoint_rel = stripped[5:].strip()
                if endpoint_rel:
                    return urljoin(f"{platform.base_url}/", endpoint_rel)
        return platform.base_url

    async def _rpc_call(
        self,
        db: AsyncSession,
        platform: Platform,
        method: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        rpc_body: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": method,
            "params": params or {},
        }

        async def _send(injection: AuthInjection) -> httpx.Response:
            target_url = await self._resolve_rpc_url(platform, injection)
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                **platform.extra_headers,
                **injection.headers,
            }
            return await self._auth_engine._http_request(
                "POST",
                target_url,
                timeout_ms=platform.timeout_ms,
                headers=headers,
                params=injection.query_params or None,
                json_body=rpc_body,
            )

        response, _retried = await self._auth_engine.execute_http_with_auth_retry(
            db,
            platform,
            _send,
        )
        if response.status_code >= 400:
            raise UpstreamMcpError(
                f"Upstream MCP '{method}' failed with HTTP {response.status_code}: "
                f"{response.text[:300]}"
            )
        payload = _parse_mcp_http_response(response)
        if "error" in payload and payload["error"] is not None:
            err = payload["error"]
            msg = err.get("message") if isinstance(err, dict) else str(err)
            raise UpstreamMcpError(f"Upstream MCP error on '{method}': {msg}")
        result = payload.get("result")
        return result if isinstance(result, dict) else {"value": result}

    async def list_tools(self, db: AsyncSession, platform: Platform) -> list[dict[str, Any]]:
        result = await self._rpc_call(db, platform, "tools/list", {})
        tools = result.get("tools")
        if not isinstance(tools, list):
            return []
        return [t for t in tools if isinstance(t, dict) and t.get("name")]

    async def call_tool(
        self,
        db: AsyncSession,
        platform: Platform,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self._rpc_call(
            db,
            platform,
            "tools/call",
            {"name": tool_name, "arguments": arguments},
        )
