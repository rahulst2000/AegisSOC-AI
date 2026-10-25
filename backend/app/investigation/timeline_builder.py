import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.event import SecurityEvent
from app.models.evidence import Evidence


def ensure_utc(dt: datetime | None) -> datetime:
    if dt is None:
        return datetime.now(UTC)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


async def build_investigation_timeline(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    event_ids: list[str],
) -> list[dict[str, Any]]:
    """
    Constructs an evidence-linked forensic timeline from specific event IDs.
    Each timeline entry links to its SecurityEvent and forensic SHA-256 integrity hash.
    """
    if not event_ids:
        return []

    parsed_uuids: list[uuid.UUID] = []
    for eid in event_ids:
        try:
            parsed_uuids.append(uuid.UUID(str(eid)))
        except ValueError:
            continue

    if not parsed_uuids:
        return []

    # Fetch events
    evt_stmt = select(SecurityEvent).where(
        SecurityEvent.id.in_(parsed_uuids),
        SecurityEvent.tenant_id == tenant_id,
    )
    evt_res = await db.execute(evt_stmt)
    events = evt_res.scalars().all()

    # Fetch linked evidence items to include integrity hashes
    ev_stmt = select(Evidence).where(
        Evidence.event_id.in_(parsed_uuids),
        Evidence.tenant_id == tenant_id,
    )
    ev_res = await db.execute(ev_stmt)
    ev_records = {e.event_id: e for e in ev_res.scalars().all()}

    items: list[dict[str, Any]] = []
    for evt in events:
        evidence = ev_records.get(evt.id)
        items.append(
            {
                "timestamp": ensure_utc(evt.timestamp).isoformat(),
                "event_id": str(evt.id),
                "event_type": evt.event_type,
                "severity": evt.severity,
                "source_ip": evt.source_ip,
                "destination_ip": (
                    evt.normalized_event.get("destination", {}).get("ip")
                    if isinstance(evt.normalized_event, dict)
                    else None
                ),
                "user_name": evt.username,
                "hostname": evt.hostname,
                "integrity_hash": evidence.integrity_hash if evidence else None,
                "description": (
                    f"Event {evt.event_type} on host '{evt.hostname or 'unknown'}' by '{evt.username or 'unknown'}'"
                ),
            }
        )

    # Sort strictly chronologically
    items.sort(key=lambda x: x["timestamp"])
    return items
