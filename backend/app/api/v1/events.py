import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_tenant_context, require_roles
from app.schemas.event import SecurityEventCreate, SecurityEventRead
from app.security.roles import Role
from app.security.tenant import TenantContext
from app.services.event_service import (
    create_security_event,
    get_security_event_by_id,
    get_security_events,
)

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
    severity: str | None = Query(None),
    event_type: str | None = Query(None),
    source: str | None = Query(None),
    source_ip: str | None = Query(None),
    username: str | None = Query(None),
    search: str | None = Query(None),
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieves events strictly bounded to the authenticated tenant with optional filters.
    """
    return await get_security_events(
        db=db,
        tenant_id=ctx.tenant_id,
        skip=skip,
        limit=limit,
        severity=severity,
        event_type=event_type,
        source=source,
        source_ip=source_ip,
        username=username,
        search=search,
    )


@router.get("/{event_id}", response_model=SecurityEventRead, status_code=status.HTTP_200_OK)
async def get_event(
    event_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieves a single security event by ID within the authenticated tenant.
    """
    event = await get_security_event_by_id(
        db=db,
        tenant_id=ctx.tenant_id,
        event_id=event_id,
    )
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security event not found",
        )
    return event
