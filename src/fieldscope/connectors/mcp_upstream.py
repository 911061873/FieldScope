from __future__ import annotations

import asyncio
import json
import uuid
from typing import Any

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from fieldscope.auth_engine.engine import AuthEngine, AuthInjection
from fieldscope.db.models import Platform

MCP_PROTOCOL_VERSION = "2025-03-26"


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
    """Remote MCP Streamable HTTP client with initialize handshake and Mcp-Session-Id lifecycle."""

    def __init__(self, auth_engine: AuthEngine) -> None:
        self._auth_engine = auth_engine
        # platform_id -> session_id ("" means initialized stateless server without session header)
        self._sessions: dict[int, str] = {}
        self._session_locks: dict[int, asyncio.Lock] = {}

    def _get_lock(self, platform_id: int) -> asyncio.Lock:
        lock = self._session_locks.get(platform_id)
        if lock is None:
            lock = asyncio.Lock()
            self._session_locks[platform_id] = lock
        return lock

    def invalidate_session(self, platform_id: int) -> None:
        self._sessions.pop(platform_id, None)

    def _validate_transport(self, platform: Platform) -> None:
        if platform.mcp_transport == "sse":
            raise UpstreamMcpError(
                "Legacy MCP SSE transport is not supported in this release; "
                "configure platform mcp_transport as 'streamable_http'."
            )

    def _build_headers(
        self,
        platform: Platform,
        injection: AuthInjection,
        *,
        session_id: str | None = None,
    ) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
            **platform.extra_headers,
            **injection.headers,
        }
        if session_id:
            headers["Mcp-Session-Id"] = session_id
        return headers

    async def _ensure_initialized(
        self,
        db: AsyncSession,
        platform: Platform,
        *,
        force_reinit: bool = False,
    ) -> str:
        """Perform MCP Streamable HTTP initialize + notifications/initialized handshake."""
        if not force_reinit and platform.id in self._sessions:
            return self._sessions[platform.id]

        async with self._get_lock(platform.id):
            if not force_reinit and platform.id in self._sessions:
                return self._sessions[platform.id]

            init_body: dict[str, Any] = {
                "jsonrpc": "2.0",
                "id": str(uuid.uuid4()),
                "method": "initialize",
                "params": {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "FieldScope", "version": "0.1.0"},
                },
            }

            async def _send_init(injection: AuthInjection) -> httpx.Response:
                return await self._auth_engine.send_http_request(
                    "POST",
                    platform.base_url,
                    timeout_ms=platform.timeout_ms,
                    headers=self._build_headers(platform, injection),
                    params=injection.query_params or None,
                    json_body=init_body,
                )

            resp, _ = await self._auth_engine.execute_http_with_auth_retry(
                db,
                platform,
                _send_init,
            )

            # Stateless minimal servers may return 404/405 or JSON-RPC -32601 for initialize
            if resp.status_code >= 400:
                self._sessions[platform.id] = ""
                return ""

            try:
                parsed = _parse_mcp_http_response(resp)
            except UpstreamMcpError:
                self._sessions[platform.id] = ""
                return ""

            if parsed.get("error"):
                err = parsed["error"]
                code = err.get("code") if isinstance(err, dict) else None
                if code == -32601:
                    self._sessions[platform.id] = ""
                    return ""
                msg = err.get("message") if isinstance(err, dict) else str(err)
                raise UpstreamMcpError(f"Upstream MCP initialize failed: {msg}")

            session_id = resp.headers.get("mcp-session-id") or ""
            self._sessions[platform.id] = session_id

            # Send notifications/initialized (best-effort notification per MCP spec)
            notif_body = {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
            }

            async def _send_notif(injection: AuthInjection) -> httpx.Response:
                return await self._auth_engine.send_http_request(
                    "POST",
                    platform.base_url,
                    timeout_ms=platform.timeout_ms,
                    headers=self._build_headers(platform, injection, session_id=session_id),
                    params=injection.query_params or None,
                    json_body=notif_body,
                )

            try:
                await self._auth_engine.execute_http_with_auth_retry(db, platform, _send_notif)
            except httpx.HTTPError:
                pass

            return session_id

    async def _rpc_call(
        self,
        db: AsyncSession,
        platform: Platform,
        method: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._validate_transport(platform)
        session_id = await self._ensure_initialized(db, platform)

        for attempt in range(2):
            rpc_body: dict[str, Any] = {
                "jsonrpc": "2.0",
                "id": str(uuid.uuid4()),
                "method": method,
                "params": params or {},
            }

            async def _send(
                injection: AuthInjection,
                *,
                sid: str = session_id,
                body: dict[str, Any] = rpc_body,
            ) -> httpx.Response:
                return await self._auth_engine.send_http_request(
                    "POST",
                    platform.base_url,
                    timeout_ms=platform.timeout_ms,
                    headers=self._build_headers(platform, injection, session_id=sid),
                    params=injection.query_params or None,
                    json_body=body,
                )

            response, _retried = await self._auth_engine.execute_http_with_auth_retry(
                db,
                platform,
                _send,
            )

            # Per Streamable HTTP spec, HTTP 404 (or 400 session invalid) means session expired
            if response.status_code in (400, 404) and session_id and attempt == 0:
                self.invalidate_session(platform.id)
                session_id = await self._ensure_initialized(db, platform, force_reinit=True)
                continue

            if response.status_code >= 400:
                raise UpstreamMcpError(
                    f"Upstream MCP '{method}' failed with HTTP {response.status_code}: "
                    f"{response.text[:300]}"
                )

            # Update session id if server rotated/returned one
            returned_sid = response.headers.get("mcp-session-id")
            if returned_sid:
                self._sessions[platform.id] = returned_sid

            payload = _parse_mcp_http_response(response)
            if "error" in payload and payload["error"] is not None:
                err = payload["error"]
                msg = err.get("message") if isinstance(err, dict) else str(err)
                raise UpstreamMcpError(f"Upstream MCP error on '{method}': {msg}")
            result = payload.get("result")
            return result if isinstance(result, dict) else {"value": result}

        raise UpstreamMcpError(f"Upstream MCP '{method}' failed after session re-initialization")

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
