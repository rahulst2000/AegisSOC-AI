import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.escalation.models import L2Escalation
from app.escalation.package_builder import build_l2_investigation_package
from app.investigation.models import Investigation
from app.models.incident import Incident
from app.services.audit_service import log_audit_event


async def escalate_incident(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
    reason: str,
    urgency: str = "HIGH",
    user_id: uuid.UUID | None = None,
) -> L2Escalation:
    """Creates a Tier-2 SOC escalation record and packages full investigation context."""
    # Fetch incident
    inc_stmt = select(Incident).where(Incident.id == incident_id, Incident.tenant_id == tenant_id)
    inc_res = await db.execute(inc_stmt)
    incident = inc_res.scalars().first()
    if not incident:
        raise ValueError(f"Incident {incident_id} not found for tenant {tenant_id}")

    # Fetch investigation ID if available
    inv_stmt = (
        select(Investigation.id)
        .where(
            Investigation.incident_id == incident_id,
            Investigation.tenant_id == tenant_id,
        )
        .order_by(Investigation.created_at.desc())
    )
    inv_res = await db.execute(inv_stmt)
    investigation_id = inv_res.scalars().first()

    # Build full package
    package = await build_l2_investigation_package(
        db=db,
        tenant_id=tenant_id,
        incident_id=incident_id,
        reason=reason,
        urgency=urgency,
    )

    escalation = L2Escalation(
        incident_id=incident_id,
        investigation_id=investigation_id,
        tenant_id=tenant_id,
        escalated_by=user_id,
        escalated_at=datetime.now(UTC),
        reason=reason,
        urgency=urgency,
        status="OPEN",
        l2_package=package,
    )
    db.add(escalation)

    # Update incident status to ESCALATED
    incident.status = "ESCALATED"
    await db.flush()

    await log_audit_event(
        db=db,
        tenant_id=tenant_id,
        user_id=user_id,
        action="L2_ESCALATION_CREATED",
        resource_type="l2_escalation",
        resource_id=str(escalation.id),
        result="SUCCESS",
        metadata={
            "incident_id": str(incident_id),
            "urgency": urgency,
            "reason": reason,
        },
    )
    return escalation


async def get_escalation_by_incident(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
) -> L2Escalation | None:
    """Retrieves active L2 escalation record for an incident."""
    stmt = (
        select(L2Escalation)
        .where(
            L2Escalation.incident_id == incident_id,
            L2Escalation.tenant_id == tenant_id,
        )
        .order_by(L2Escalation.escalated_at.desc())
    )
    res = await db.execute(stmt)
    return res.scalars().first()
