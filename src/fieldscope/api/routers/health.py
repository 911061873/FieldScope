from __future__ import annotations

from fastapi import APIRouter, Depends

from fieldscope.api.deps import DataPlanePrincipal, resolve_data_plane_principal
from fieldscope.schemas.auth import DataPlanePrincipalResponse
from fieldscope.schemas.common import RoleBrief

router = APIRouter(tags=["system"])


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/api/v1/data-plane/whoami", response_model=DataPlanePrincipalResponse)
async def data_plane_whoami(
    principal: DataPlanePrincipal = Depends(resolve_data_plane_principal),
) -> DataPlanePrincipalResponse:
    """Diagnostic endpoint verifying dual-mode data-plane authentication (User Key / App Key)."""
    user = principal.user
    return DataPlanePrincipalResponse(
        auth_mode=principal.auth_mode,
        user_id=user.id,
        username=user.username,
        display_name=user.display_name,
        department=user.department,
        attributes=user.attributes,
        external_roles=[
            RoleBrief.model_validate(r) for r in user.external_roles if r.is_active
        ],
        app_id=principal.app.id if principal.app else None,
        app_code=principal.app.app_code if principal.app else None,
    )
