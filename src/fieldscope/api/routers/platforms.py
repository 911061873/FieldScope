from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from fieldscope.api.deps import require_permissions
from fieldscope.auth_engine.engine import AuthEngine, AuthEngineError
from fieldscope.connectors.mcp_upstream import UpstreamMcpClient, UpstreamMcpError
from fieldscope.db.models import Platform, PlatformEndpoint, User
from fieldscope.db.session import get_db
from fieldscope.schemas.common import MessageResponse
from fieldscope.schemas.platform import (
    PlatformCreate,
    PlatformEndpointCreate,
    PlatformEndpointRead,
    PlatformEndpointUpdate,
    PlatformRead,
    PlatformUpdate,
)

router = APIRouter(prefix="/api/v1/admin/platforms", tags=["platforms"])


async def _load_platform(db: AsyncSession, platform_id: int) -> Platform | None:
    return await db.scalar(
        select(Platform)
        .where(Platform.id == platform_id)
        .options(selectinload(Platform.endpoints))
    )


@router.get("", response_model=list[PlatformRead])
async def list_platforms(
    _admin: User = Depends(require_permissions("platform:read")),
    db: AsyncSession = Depends(get_db),
) -> list[PlatformRead]:
    rows = (
        await db.scalars(
            select(Platform)
            .options(selectinload(Platform.endpoints))
            .order_by(Platform.id.asc())
        )
    ).all()
    return [PlatformRead.model_validate(p) for p in rows]


@router.post("", response_model=PlatformRead, status_code=status.HTTP_201_CREATED)
async def create_platform(
    body: PlatformCreate,
    _admin: User = Depends(require_permissions("platform:write")),
    db: AsyncSession = Depends(get_db),
) -> PlatformRead:
    exists = await db.scalar(select(Platform.id).where(Platform.code == body.code))
    if exists is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Platform code '{body.code}' already exists",
        )
    platform = Platform(
        code=body.code,
        name=body.name,
        description=body.description,
        protocol_type=body.protocol_type,
        base_url=body.base_url.rstrip("/"),
        mcp_transport=body.mcp_transport if body.protocol_type == "mcp" else None,
        timeout_ms=body.timeout_ms,
        extra_headers=body.extra_headers,
        is_active=body.is_active,
    )
    db.add(platform)
    await db.commit()
    loaded = await _load_platform(db, platform.id)
    return PlatformRead.model_validate(loaded)


@router.get("/{platform_id}", response_model=PlatformRead)
async def get_platform(
    platform_id: int,
    _admin: User = Depends(require_permissions("platform:read")),
    db: AsyncSession = Depends(get_db),
) -> PlatformRead:
    platform = await _load_platform(db, platform_id)
    if platform is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Platform not found")
    return PlatformRead.model_validate(platform)


@router.patch("/{platform_id}", response_model=PlatformRead)
async def update_platform(
    platform_id: int,
    body: PlatformUpdate,
    _admin: User = Depends(require_permissions("platform:write")),
    db: AsyncSession = Depends(get_db),
) -> PlatformRead:
    platform = await _load_platform(db, platform_id)
    if platform is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Platform not found")
    if body.name is not None:
        platform.name = body.name
    if body.description is not None:
        platform.description = body.description
    if body.base_url is not None:
        platform.base_url = body.base_url.rstrip("/")
    if body.mcp_transport is not None and platform.protocol_type == "mcp":
        platform.mcp_transport = body.mcp_transport
    if body.timeout_ms is not None:
        platform.timeout_ms = body.timeout_ms
    if body.extra_headers is not None:
        platform.extra_headers = body.extra_headers
    if body.is_active is not None:
        platform.is_active = body.is_active
    await db.commit()
    loaded = await _load_platform(db, platform.id)
    return PlatformRead.model_validate(loaded)


@router.delete("/{platform_id}", response_model=MessageResponse)
async def delete_platform(
    platform_id: int,
    _admin: User = Depends(require_permissions("platform:write")),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    platform = await db.scalar(select(Platform).where(Platform.id == platform_id))
    if platform is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Platform not found")
    await db.delete(platform)
    await db.commit()
    return MessageResponse(message="Platform deleted")


@router.get("/{platform_id}/endpoints", response_model=list[PlatformEndpointRead])
async def list_platform_endpoints(
    platform_id: int,
    _admin: User = Depends(require_permissions("platform:read")),
    db: AsyncSession = Depends(get_db),
) -> list[PlatformEndpointRead]:
    exists = await db.scalar(select(Platform.id).where(Platform.id == platform_id))
    if exists is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Platform not found")
    rows = (
        await db.scalars(
            select(PlatformEndpoint)
            .where(PlatformEndpoint.platform_id == platform_id)
            .order_by(PlatformEndpoint.id.asc())
        )
    ).all()
    return [PlatformEndpointRead.model_validate(e) for e in rows]


@router.post(
    "/{platform_id}/endpoints",
    response_model=PlatformEndpointRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_platform_endpoint(
    platform_id: int,
    body: PlatformEndpointCreate,
    _admin: User = Depends(require_permissions("platform:write")),
    db: AsyncSession = Depends(get_db),
) -> PlatformEndpointRead:
    platform = await db.scalar(select(Platform).where(Platform.id == platform_id))
    if platform is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Platform not found")

    dup = await db.scalar(
        select(PlatformEndpoint.id).where(
            PlatformEndpoint.platform_id == platform_id,
            PlatformEndpoint.code == body.code,
        )
    )
    if dup is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Endpoint code '{body.code}' already exists on platform '{platform.code}'",
        )

    endpoint = PlatformEndpoint(
        platform_id=platform_id,
        resource_type=body.resource_type,
        code=body.code,
        name=body.name,
        description=body.description,
        method=body.method.upper() if body.method else None,
        path_pattern=body.path_pattern,
        expose_as_mcp=body.expose_as_mcp,
        mcp_tool_name=body.mcp_tool_name or f"{platform.code}_{body.code}",
        input_schema=body.input_schema,
        output_schema=body.output_schema,
        is_active=body.is_active,
    )
    db.add(endpoint)
    await db.commit()
    await db.refresh(endpoint)
    return PlatformEndpointRead.model_validate(endpoint)


@router.patch("/{platform_id}/endpoints/{endpoint_id}", response_model=PlatformEndpointRead)
async def update_platform_endpoint(
    platform_id: int,
    endpoint_id: int,
    body: PlatformEndpointUpdate,
    _admin: User = Depends(require_permissions("platform:write")),
    db: AsyncSession = Depends(get_db),
) -> PlatformEndpointRead:
    endpoint = await db.scalar(
        select(PlatformEndpoint).where(
            PlatformEndpoint.id == endpoint_id,
            PlatformEndpoint.platform_id == platform_id,
        )
    )
    if endpoint is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Endpoint not found")
    if body.name is not None:
        endpoint.name = body.name
    if body.description is not None:
        endpoint.description = body.description
    if body.method is not None:
        endpoint.method = body.method.upper()
    if body.path_pattern is not None:
        endpoint.path_pattern = body.path_pattern
    if body.expose_as_mcp is not None:
        endpoint.expose_as_mcp = body.expose_as_mcp
    if body.mcp_tool_name is not None:
        endpoint.mcp_tool_name = body.mcp_tool_name
    if body.input_schema is not None:
        endpoint.input_schema = body.input_schema
    if body.output_schema is not None:
        endpoint.output_schema = body.output_schema
    if body.is_active is not None:
        endpoint.is_active = body.is_active
    await db.commit()
    await db.refresh(endpoint)
    return PlatformEndpointRead.model_validate(endpoint)


@router.delete("/{platform_id}/endpoints/{endpoint_id}", response_model=MessageResponse)
async def delete_platform_endpoint(
    platform_id: int,
    endpoint_id: int,
    _admin: User = Depends(require_permissions("platform:write")),
    db: AsyncSession = Depends(get_db),
) -> MessageResponse:
    endpoint = await db.scalar(
        select(PlatformEndpoint).where(
            PlatformEndpoint.id == endpoint_id,
            PlatformEndpoint.platform_id == platform_id,
        )
    )
    if endpoint is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Endpoint not found")
    await db.delete(endpoint)
    await db.commit()
    return MessageResponse(message="Endpoint deleted")


@router.post("/{platform_id}/sync-mcp-tools", response_model=list[PlatformEndpointRead])
async def sync_upstream_mcp_tools(
    platform_id: int,
    request: Request,
    _admin: User = Depends(require_permissions("platform:write")),
    db: AsyncSession = Depends(get_db),
) -> list[PlatformEndpointRead]:
    """Fetch tools/list from a remote MCP platform and upsert them as managed endpoints."""
    platform = await _load_platform(db, platform_id)
    if platform is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Platform not found")
    if platform.protocol_type != "mcp":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only MCP platforms support syncing upstream MCP tools",
        )

    auth_engine: AuthEngine = request.app.state.auth_engine
    mcp_client = UpstreamMcpClient(auth_engine)
    try:
        upstream_tools = await mcp_client.list_tools(db, platform)
    except (AuthEngineError, UpstreamMcpError) as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to sync upstream MCP tools: {exc}",
        ) from exc

    existing_by_code = {ep.code: ep for ep in platform.endpoints}
    for tool in upstream_tools:
        tool_code = str(tool["name"])
        tool_desc = str(tool.get("description") or "")
        input_schema = tool.get("inputSchema") or {"type": "object", "properties": {}}
        exposed_name = f"{platform.code}_{tool_code}"

        ep = existing_by_code.get(tool_code)
        if ep is None:
            ep = PlatformEndpoint(
                platform_id=platform.id,
                resource_type="mcp_tool",
                code=tool_code,
                name=tool_code,
                description=tool_desc,
                method=None,
                path_pattern=None,
                expose_as_mcp=True,
                mcp_tool_name=exposed_name,
                input_schema=input_schema,
                output_schema={},
                is_active=True,
            )
            db.add(ep)
        else:
            ep.resource_type = "mcp_tool"
            ep.description = tool_desc
            ep.input_schema = input_schema
            if not ep.mcp_tool_name:
                ep.mcp_tool_name = exposed_name

    await db.commit()
    rows = (
        await db.scalars(
            select(PlatformEndpoint)
            .where(PlatformEndpoint.platform_id == platform_id)
            .order_by(PlatformEndpoint.id.asc())
        )
    ).all()
    return [PlatformEndpointRead.model_validate(e) for e in rows]

