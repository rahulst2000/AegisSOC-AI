import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.ai.gateway import get_ai_provider
from app.ai.schemas import AIActionRecommendation
from app.investigation.investigator import run_investigation
from app.investigation.models import Investigation, InvestigationHypothesis
from app.models.incident import Incident


async def get_or_run_investigation(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
    force_refresh: bool = False,
    analyst_notes: str | None = None,
    user_id: uuid.UUID | None = None,
) -> Investigation:
    """Gets existing investigation or executes a fresh one."""
    return await run_investigation(
        db=db,
        tenant_id=tenant_id,
        incident_id=incident_id,
        force_refresh=force_refresh,
        analyst_notes=analyst_notes,
        user_id=user_id,
    )


async def get_investigation_by_incident(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
) -> Investigation | None:
    """Retrieves existing investigation for an incident without executing a new one."""
    stmt = (
        select(Investigation)
        .where(
            Investigation.incident_id == incident_id,
            Investigation.tenant_id == tenant_id,
        )
        .options(
            selectinload(Investigation.hypotheses),
            selectinload(Investigation.findings),
        )
        .order_by(Investigation.created_at.desc())
    )
    res = await db.execute(stmt)
    return res.scalars().first()


async def get_hypotheses_by_incident(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
) -> list[InvestigationHypothesis]:
    """Retrieves hypotheses for an incident."""
    inv = await get_investigation_by_incident(db, tenant_id, incident_id)
    if not inv:
        return []
    return inv.hypotheses


async def get_recommendations_by_incident(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
) -> list[AIActionRecommendation]:
    """Retrieves AI-recommended response actions for an incident."""
    inv = await get_investigation_by_incident(db, tenant_id, incident_id)
    if not inv:
        inv = await run_investigation(db, tenant_id, incident_id)

    # Re-evaluate recommendations from AI provider given the current incident state
    stmt = select(Incident).where(Incident.id == incident_id, Incident.tenant_id == tenant_id)
    res = await db.execute(stmt)
    incident = res.scalars().first()
    if not incident:
        return []

    context = {
        "incident": {
            "id": str(incident.id),
            "title": incident.title,
            "risk_score": incident.risk_score,
            "confidence_score": getattr(incident, "confidence", 0.0),
            "mitre_techniques": incident.mitre_techniques or [],
            "affected_assets": incident.affected_assets or [],
            "affected_users": incident.affected_users or [],
            "source_ips": incident.source_ips or [],
        },
        "detections": [],
        "events": [],
    }
    ai_provider = get_ai_provider()
    return await ai_provider.recommend_actions(context)
