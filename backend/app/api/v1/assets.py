from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_tenant_context, require_roles
from app.schemas.asset import AssetCreate, AssetRead
from app.security.roles import Role
from app.security.tenant import TenantContext
from app.services.asset_service import create_asset, get_assets

router = APIRouter(prefix="/assets", tags=["Assets"])


@router.post(
    "",
    response_model=AssetRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(
            require_roles(
                [
                    Role.TENANT_ADMIN,
                    Role.SECURITY_ENGINEER,
                    Role.SOC_L2,
                    Role.SECURITY_MANAGER,
                ]
            )
        )
    ],
)
async def create_new_asset(
    asset_in: AssetCreate,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """
    Registers a new infrastructure asset.
    Tenant identity is strictly derived from the authenticated token context.
    """
    return await create_asset(
        db=db,
        tenant_id=ctx.tenant_id,
        asset_in=asset_in,
        user_id=ctx.user_id,
    )


@router.get("", response_model=list[AssetRead], status_code=status.HTTP_200_OK)
async def list_assets(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """
    Lists all assets belonging strictly to the authenticated caller's tenant.
    Cross-tenant queries are strictly denied.
    """
    return await get_assets(
        db=db,
        tenant_id=ctx.tenant_id,
        skip=skip,
        limit=limit,
    )
