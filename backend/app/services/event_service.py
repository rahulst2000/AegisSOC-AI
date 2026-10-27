import uuid
from datetime import UTC, datetime

from sqlalchemy import or_, select
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
    severity: str | None = None,
    event_type: str | None = None,
    source: str | None = None,
    source_ip: str | None = None,
    username: str | None = None,
    search: str | None = None,
) -> list[SecurityEvent]:
    """
    Fetches events with strict tenant boundary filtering and optional attribute filters.
    """
    stmt = select(SecurityEvent).where(SecurityEvent.tenant_id == tenant_id)

    if severity:
        stmt = stmt.where(SecurityEvent.severity == severity.upper())
    if event_type:
        stmt = stmt.where(SecurityEvent.event_type.ilike(f"%{event_type}%"))
    if source:
        stmt = stmt.where(SecurityEvent.source.ilike(f"%{source}%"))
    if source_ip:
        stmt = stmt.where(SecurityEvent.source_ip == source_ip)
    if username:
        stmt = stmt.where(SecurityEvent.username.ilike(f"%{username}%"))
    if search:
        search_term = f"%{search}%"
        stmt = stmt.where(
            or_(
                SecurityEvent.event_type.ilike(search_term),
                SecurityEvent.source.ilike(search_term),
                SecurityEvent.source_ip.ilike(search_term),
                SecurityEvent.hostname.ilike(search_term),
                SecurityEvent.username.ilike(search_term),
            )
        )

    stmt = stmt.order_by(SecurityEvent.timestamp.desc()).offset(skip).limit(limit)
    result = await db.execute(stmt)
    return list(result.scalars().all())


async def get_security_event_by_id(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    event_id: uuid.UUID,
) -> SecurityEvent | None:
    """
    Fetches a single event by ID with strict tenant boundary enforcement.
    """
    stmt = select(SecurityEvent).where(
        SecurityEvent.tenant_id == tenant_id,
        SecurityEvent.id == event_id,
    )
    result = await db.execute(stmt)
    return result.scalar_one_or_none()
