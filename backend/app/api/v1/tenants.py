from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_tenant_context, require_roles
from app.schemas.tenant import TenantCreate, TenantRead
from app.security.roles import Role
from app.security.tenant import TenantContext
from app.services.tenant_service import create_tenant, get_tenant_by_id

router = APIRouter(prefix="/tenants", tags=["Tenants"])


@router.post(
    "",
    response_model=TenantRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_roles([Role.TENANT_ADMIN, Role.CISO]))],
)
async def create_new_tenant(
    tenant_in: TenantCreate,
    db: AsyncSession = Depends(get_db),
):
    """
    Provisions a new tenant organization. Restricted to administrative roles.
    """
    return await create_tenant(db=db, tenant_in=tenant_in)


@router.get("/me", response_model=TenantRead, status_code=status.HTTP_200_OK)
async def get_current_tenant(
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """
    Returns the metadata of the tenant organization belonging to the current user.
    """
    tenant = await get_tenant_by_id(db=db, tenant_id=ctx.tenant_id)
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found.",
        )
    return tenant
