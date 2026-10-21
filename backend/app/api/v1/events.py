from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_tenant_context, require_roles
from app.schemas.event import SecurityEventCreate, SecurityEventRead
from app.security.roles import Role
from app.security.tenant import TenantContext
from app.services.event_service import create_security_event, get_security_events

router = APIRouter(prefix="/events", tags=["Security Events"])


@router.post(
    "",
    response_model=SecurityEventRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(
            require_roles(
                [
                    Role.TENANT_ADMIN,
                    Role.SECURITY_ENGINEER,
                    Role.SOC_L1,
                    Role.SOC_L2,
                    Role.SECURITY_MANAGER,
                ]
            )
        )
    ],
)
async def ingest_event(
    event_in: SecurityEventCreate,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """
    Ingests telemetry and security events into the tenant's security event lake.
    Tenant identity is strictly enforced server-side.
    """
    return await create_security_event(
        db=db,
        tenant_id=ctx.tenant_id,
        event_in=event_in,
        user_id=ctx.user_id,
    )


@router.get("", response_model=list[SecurityEventRead], status_code=status.HTTP_200_OK)
async def list_events(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieves events strictly bounded to the authenticated tenant.
    """
    return await get_security_events(
        db=db,
        tenant_id=ctx.tenant_id,
        skip=skip,
        limit=limit,
    )
