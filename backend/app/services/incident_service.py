import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert
from app.models.incident import Incident
from app.schemas.incident import IncidentCreate, IncidentStats
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


def _apply_incident_filters(
    stmt,
    tenant_id: uuid.UUID,
    severity: str | None = None,
    status: str | None = None,
    time_window: str | None = None,
):
    stmt = stmt.where(Incident.tenant_id == tenant_id)
    if severity and severity.upper() != "ALL":
        stmt = stmt.where(Incident.severity == severity.upper())
    if status and status.upper() != "ALL":
        stmt = stmt.where(Incident.status == status.upper())
    if time_window and time_window.lower() != "all":
        now = datetime.now(UTC)
        windows = {
            "15m": timedelta(minutes=15),
            "1h": timedelta(hours=1),
            "24h": timedelta(hours=24),
            "7d": timedelta(days=7),
        }
        delta = windows.get(time_window.lower())
        if delta:
            cutoff = now - delta
            stmt = stmt.where(Incident.created_at >= cutoff)
    return stmt


async def get_incidents(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    skip: int = 0,
    limit: int = 100,
    severity: str | None = None,
    status: str | None = None,
    time_window: str | None = None,
) -> list[Incident]:
    """Retrieves incidents for the tenant filtered by severity, status, and time window."""
    stmt = select(Incident)
    stmt = _apply_incident_filters(
        stmt=stmt,
        tenant_id=tenant_id,
        severity=severity,
        status=status,
        time_window=time_window,
    )
    stmt = stmt.order_by(Incident.created_at.desc()).offset(skip).limit(limit)
    result = await db.execute(stmt)
    return list(result.scalars().all())


async def get_incident_stats(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    severity: str | None = None,
    status: str | None = None,
    time_window: str | None = None,
) -> IncidentStats:
    """Calculates authoritative aggregate attack metrics matching active filters."""
    stmt = select(Incident)
    stmt = _apply_incident_filters(
        stmt=stmt,
        tenant_id=tenant_id,
        severity=severity,
        status=status,
        time_window=time_window,
    )
    result = await db.execute(stmt)
    matched_incidents = list(result.scalars().all())

    total = len(matched_incidents)
    crit = sum(1 for i in matched_incidents if i.severity == "CRITICAL")
    high = sum(1 for i in matched_incidents if i.severity == "HIGH")
    med = sum(1 for i in matched_incidents if i.severity == "MEDIUM")
    low = sum(1 for i in matched_incidents if i.severity == "LOW")
    open_inc = sum(1 for i in matched_incidents if i.status == "OPEN")
    investigating = sum(1 for i in matched_incidents if i.status == "INVESTIGATING")
    resolved = sum(1 for i in matched_incidents if i.status in ("RESOLVED", "CLOSED"))
    max_risk = max((i.risk_score for i in matched_incidents), default=0.0)

    if crit > 0:
        posture_status = "CRITICAL THREAT"
        posture_color = "#f43f5e"
    elif high > 0:
        posture_status = "ELEVATED RISK"
        posture_color = "#f59e0b"
    elif open_inc > 0:
        posture_status = "GUARDED"
        posture_color = "#38bdf8"
    else:
        posture_status = "NOMINAL"
        posture_color = "#10b981"

    return IncidentStats(
        total_count=total,
        critical_count=crit,
        high_count=high,
        medium_count=med,
        low_count=low,
        open_count=open_inc,
        investigating_count=investigating,
        resolved_count=resolved,
        max_risk_score=max_risk,
        posture_status=posture_status,
        posture_color=posture_color,
    )


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
