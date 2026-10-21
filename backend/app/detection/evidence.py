import hashlib
import json
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.event import SecurityEvent
from app.models.evidence import Evidence


def compute_evidence_hash(event: SecurityEvent) -> str:
    """
    Computes a deterministic cryptographic SHA-256 integrity hash from the
    original event telemetry, guaranteeing forensic immutability.
    """
    raw_payload_bytes = json.dumps(
        event.raw_event,
        sort_keys=True,
        default=str,
    ).encode("utf-8")

    digest = hashlib.sha256()
    digest.update(str(event.id).encode("utf-8"))
    digest.update(str(event.tenant_id).encode("utf-8"))
    digest.update(event.timestamp.isoformat().encode("utf-8"))
    digest.update(raw_payload_bytes)
    return digest.hexdigest()


async def link_event_evidence(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    event: SecurityEvent,
    description: str,
    incident_id: uuid.UUID | None = None,
) -> Evidence:
    """
    Creates an immutable Evidence record bound to the tenant and event.
    Never fabricates telemetry or event IDs.
    """
    integrity_hash = compute_evidence_hash(event)

    evidence_item = Evidence(
        tenant_id=tenant_id,
        incident_id=incident_id,
        event_id=event.id,
        evidence_type="EVENT_TELEMETRY",
        description=description,
        source=event.source,
        integrity_hash=integrity_hash,
    )
    db.add(evidence_item)
    await db.flush()
    return evidence_item
