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


@router.get("/{incident_id}/timeline", status_code=status.HTTP_200_OK)
async def get_incident_timeline_endpoint(
    incident_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieves chronological forensic timeline (events, detections, evidence)
    for an incident strictly bounded to the authenticated tenant.
    """
    from app.correlation.timeline import get_incident_timeline

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
    return await get_incident_timeline(db, ctx.tenant_id, incident_id)


@router.post(
    "/{incident_id}/investigate",
    status_code=status.HTTP_200_OK,
)
async def investigate_incident_endpoint(
    incident_id: uuid.UUID,
    payload: dict | None = None,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Triggers or forces refresh of AI-assisted evidence-grounded investigation."""
    from app.investigation.service import get_or_run_investigation

    force_refresh = (payload or {}).get("force_refresh", True)
    analyst_notes = (payload or {}).get("analyst_notes")
    try:
        inv = await get_or_run_investigation(
            db=db,
            tenant_id=ctx.tenant_id,
            incident_id=incident_id,
            force_refresh=force_refresh,
            analyst_notes=analyst_notes,
            user_id=ctx.user_id,
        )
        return inv
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.get(
    "/{incident_id}/investigation",
    status_code=status.HTTP_200_OK,
)
async def get_investigation_endpoint(
    incident_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves existing investigation for an incident."""
    from app.investigation.service import get_investigation_by_incident

    inv = await get_investigation_by_incident(
        db=db,
        tenant_id=ctx.tenant_id,
        incident_id=incident_id,
    )
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation not found for this incident. Run /investigate first.",
        )
    return inv


@router.get(
    "/{incident_id}/hypotheses",
    status_code=status.HTTP_200_OK,
)
async def get_hypotheses_endpoint(
    incident_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves evaluated hypotheses for an incident."""
    from app.investigation.service import get_hypotheses_by_incident

    return await get_hypotheses_by_incident(
        db=db,
        tenant_id=ctx.tenant_id,
        incident_id=incident_id,
    )


@router.get(
    "/{incident_id}/recommendations",
    status_code=status.HTTP_200_OK,
)
async def get_recommendations_endpoint(
    incident_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves AI-recommended response actions for an incident."""
    from app.investigation.service import get_recommendations_by_incident

    return await get_recommendations_by_incident(
        db=db,
        tenant_id=ctx.tenant_id,
        incident_id=incident_id,
    )


@router.post(
    "/{incident_id}/escalate",
    status_code=status.HTTP_201_CREATED,
)
async def escalate_incident_endpoint(
    incident_id: uuid.UUID,
    payload: dict,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Escalates incident to Tier-2 SOC with complete packaged forensic context."""
    from app.escalation.service import escalate_incident

    reason = payload.get("reason", "Incident exceeds L1 capability or criteria")
    urgency = payload.get("urgency", "HIGH")
    try:
        escalation = await escalate_incident(
            db=db,
            tenant_id=ctx.tenant_id,
            incident_id=incident_id,
            reason=reason,
            urgency=urgency,
            user_id=ctx.user_id,
        )
        return escalation
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.get(
    "/{incident_id}/escalation",
    status_code=status.HTTP_200_OK,
)
async def get_escalation_endpoint(
    incident_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves active L2 escalation package for an incident."""
    from app.escalation.service import get_escalation_by_incident

    esc = await get_escalation_by_incident(
        db=db,
        tenant_id=ctx.tenant_id,
        incident_id=incident_id,
    )
    if not esc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No L2 escalation package found for this incident.",
        )
    return esc
