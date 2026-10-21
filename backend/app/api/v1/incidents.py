import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_tenant_context, require_roles
from app.schemas.incident import IncidentCreate, IncidentRead
from app.security.roles import Role
from app.security.tenant import TenantContext
from app.services.incident_service import create_incident, get_incident_by_id, get_incidents

router = APIRouter(prefix="/incidents", tags=["Incidents"])


@router.post(
    "",
    response_model=IncidentRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(
            require_roles(
                [
                    Role.TENANT_ADMIN,
                    Role.SOC_L1,
                    Role.SOC_L2,
                    Role.SECURITY_ENGINEER,
                    Role.SECURITY_MANAGER,
                ]
            )
        )
    ],
)
async def create_new_incident(
    incident_in: IncidentCreate,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """
    Creates a new security incident under the caller's tenant.
    """
    return await create_incident(
        db=db,
        tenant_id=ctx.tenant_id,
        incident_in=incident_in,
        user_id=ctx.user_id,
    )


@router.get("", response_model=list[IncidentRead], status_code=status.HTTP_200_OK)
async def list_incidents(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieves all incidents belonging strictly to the caller's tenant.
    """
    return await get_incidents(
        db=db,
        tenant_id=ctx.tenant_id,
        skip=skip,
        limit=limit,
    )


@router.get("/{incident_id}", response_model=IncidentRead, status_code=status.HTTP_200_OK)
async def get_incident(
    incident_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieves a single incident by ID.
    Strictly enforces tenant isolation: If the incident belongs to a different tenant,
    HTTP 404 is returned to prevent oracle enumeration attacks.
    """
    incident = await get_incident_by_id(
        db=db,
        tenant_id=ctx.tenant_id,
        incident_id=incident_id,
    )
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found.",
        )
    return incident
