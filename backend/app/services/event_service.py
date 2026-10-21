import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert
from app.models.event import SecurityEvent
from app.schemas.event import SecurityEventCreate
from app.services.audit_service import log_audit_event


async def create_security_event(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    event_in: SecurityEventCreate,
    user_id: uuid.UUID | None = None,
) -> SecurityEvent:
    """
    Ingests a raw telemetry security event into the tenant's data lake.
    Normalizes payload and produces alerts for high-severity signals.
    """
    event_time = event_in.timestamp or datetime.now(UTC)

    # Standardize normalization if not explicitly provided
    normalized = event_in.normalized_event or {
        "@timestamp": event_time.isoformat(),
        "event": {
            "kind": "event",
            "category": "security",
            "type": event_in.event_type.lower(),
            "severity": event_in.severity.upper(),
        },
        "source": {
            "name": event_in.source,
            "ip": event_in.source_ip,
        },
        "user": {
            "name": event_in.username,
        },
        "host": {
            "hostname": event_in.hostname,
        },
    }

    event = SecurityEvent(
        tenant_id=tenant_id,
        timestamp=event_time,
        source=event_in.source,
        event_type=event_in.event_type,
        severity=event_in.severity.upper(),
        source_ip=event_in.source_ip,
        username=event_in.username,
        hostname=event_in.hostname,
        raw_event=event_in.raw_event,
        normalized_event=normalized,
    )
    db.add(event)
    await db.flush()

    # Rule-based auto-alert generation for HIGH and CRITICAL events
    if event.severity in {"HIGH", "CRITICAL"}:
        alert = Alert(
            tenant_id=tenant_id,
            event_id=event.id,
            detection_rule=f"AEGIS-SIG-{event.event_type.upper()}-01",
            severity=event.severity,
            confidence=0.95,
            status="OPEN",
        )
        db.add(alert)
        await db.flush()

    await log_audit_event(
        db=db,
        tenant_id=tenant_id,
        user_id=user_id,
        action="INGEST_SECURITY_EVENT",
        resource_type="SECURITY_EVENT",
        resource_id=str(event.id),
        result="SUCCESS",
        metadata={"event_type": event.event_type, "severity": event.severity},
    )

    await db.commit()
    await db.refresh(event)

    # Enqueue event asynchronously for detection evaluation (resilient fallback if Redis unavailable)
    from app.workers.queue import enqueue_event_for_detection

    await enqueue_event_for_detection(str(event.id), str(tenant_id))

    return event


async def get_security_events(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    skip: int = 0,
    limit: int = 100,
) -> list[SecurityEvent]:
    """
    Fetches events with strict tenant boundary filtering.
    """
    stmt = (
        select(SecurityEvent)
        .where(SecurityEvent.tenant_id == tenant_id)
        .order_by(SecurityEvent.timestamp.desc())
        .offset(skip)
        .limit(limit)
    )
    result = await db.execute(stmt)
    return list(result.scalars().all())
