import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.evidence import Evidence


async def collect_assessment_evidence_ids(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    event_ids: list[uuid.UUID],
    incident_id: uuid.UUID | None = None,
) -> list[str]:
    """
    Collects immutable cryptographic Evidence records linked to simulation events or incidents.
    Never fabricates telemetry or event IDs.
    """
    if not event_ids and not incident_id:
        return []

    conditions = [Evidence.tenant_id == tenant_id]
    or_clauses = []
    if event_ids:
        or_clauses.append(Evidence.event_id.in_(event_ids))
    if incident_id:
        or_clauses.append(Evidence.incident_id == incident_id)

    from sqlalchemy import or_

    stmt = select(Evidence.id).where(*conditions, or_(*or_clauses))
    res = await db.execute(stmt)
    evidence_uuids = res.scalars().all()

    return [str(eid) for eid in evidence_uuids]
