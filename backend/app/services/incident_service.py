import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert
from app.models.incident import Incident
from app.schemas.incident import IncidentCreate
from app.services.audit_service import log_audit_event


async def get_alerts(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    skip: int = 0,
    limit: int = 100,
) -> list[Alert]:
    """Retrieves alerts strictly isolated to the authenticated tenant."""
    stmt = select(Alert).where(Alert.tenant_id == tenant_id).order_by(Alert.created_at.desc()).offset(skip).limit(limit)
    result = await db.execute(stmt)
    return list(result.scalars().all())


async def create_incident(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    incident_in: IncidentCreate,
    user_id: uuid.UUID | None = None,
) -> Incident:
    """Creates a new incident scoped to the authenticated tenant."""
    incident = Incident(
        tenant_id=tenant_id,
        title=incident_in.title,
        description=incident_in.description,
        severity=incident_in.severity.upper(),
        risk_score=incident_in.risk_score,
        confidence=incident_in.confidence,
        status=incident_in.status.upper(),
    )
    db.add(incident)
    await db.flush()

    await log_audit_event(
        db=db,
        tenant_id=tenant_id,
        user_id=user_id,
        action="CREATE_INCIDENT",
        resource_type="INCIDENT",
        resource_id=str(incident.id),
        result="SUCCESS",
        metadata={"title": incident.title, "severity": incident.severity},
    )

    await db.commit()
    await db.refresh(incident)
    return incident


async def get_incidents(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    skip: int = 0,
    limit: int = 100,
) -> list[Incident]:
    """Retrieves all incidents for the tenant."""
    stmt = (
        select(Incident)
        .where(Incident.tenant_id == tenant_id)
        .order_by(Incident.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())


async def get_incident_by_id(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
) -> Incident | None:
    """
    Retrieves a single incident by ID strictly verifying tenant ownership.
    Returns None if resource does not exist OR belongs to another tenant.
    """
    stmt = select(Incident).where(
        Incident.id == incident_id,
        Incident.tenant_id == tenant_id,
    )
    result = await db.execute(stmt)
    return result.scalar_one_or_none()
