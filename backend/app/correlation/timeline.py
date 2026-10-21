import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.detection.models import DetectionResult
from app.models.event import SecurityEvent
from app.models.evidence import Evidence
from app.models.incident import Incident


class TimelineItem(BaseModel):
    timestamp: datetime
    item_type: str = Field(..., description="DETECTION, SECURITY_EVENT, or EVIDENCE")
    id: str
    title: str
    description: str
    severity: str = "MEDIUM"
    source: str | None = None
    mitre_techniques: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


async def get_incident_timeline(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
) -> list[TimelineItem]:
    """
    Constructs a unified, chronological forensic timeline for an incident.
    Synthesizes detections, underlying security events, and evidence items.
    Strictly isolated to tenant_id.
    """
    # 1. Fetch incident with tenant verification
    stmt = select(Incident).where(
        Incident.id == incident_id,
        Incident.tenant_id == tenant_id,
    )
    res = await db.execute(stmt)
    incident = res.scalars().first()
    if not incident:
        return []

    timeline: list[TimelineItem] = []

    # 2. Fetch associated detections
    det_uuids: list[uuid.UUID] = []
    for did in incident.detection_ids or []:
        try:
            det_uuids.append(uuid.UUID(did))
        except ValueError:
            continue

    detection_map: dict[str, DetectionResult] = {}
    if det_uuids:
        det_stmt = select(DetectionResult).where(
            DetectionResult.tenant_id == tenant_id,
            DetectionResult.id.in_(det_uuids),
        )
        det_res = await db.execute(det_stmt)
        for d in det_res.scalars().all():
            detection_map[str(d.id)] = d
            timeline.append(
                TimelineItem(
                    timestamp=d.timestamp,
                    item_type="DETECTION",
                    id=str(d.id),
                    title=f"Detection: {d.title}",
                    description=d.description,
                    severity=d.severity,
                    source=f"Rule: {d.rule_id}",
                    mitre_techniques=d.mitre_techniques or [],
                    metadata={
                        "rule_id": d.rule_id,
                        "confidence": d.confidence,
                        "event_count": len(d.event_ids or []),
                        "detection_count": d.detection_count,
                    },
                )
            )

    # 3. Fetch evidence items linked to incident
    ev_stmt = select(Evidence).where(
        Evidence.tenant_id == tenant_id,
        Evidence.incident_id == incident_id,
    )
    ev_res = await db.execute(ev_stmt)
    evidence_items = list(ev_res.scalars().all())

    event_ids_from_evidence: set[uuid.UUID] = set()
    for ev in evidence_items:
        if ev.event_id:
            event_ids_from_evidence.add(ev.event_id)
        timeline.append(
            TimelineItem(
                timestamp=ev.created_at,
                item_type="EVIDENCE",
                id=str(ev.id),
                title=f"Evidence: {ev.evidence_type}",
                description=ev.description,
                severity=incident.severity,
                source=ev.source,
                mitre_techniques=[],
                metadata={
                    "event_id": str(ev.event_id) if ev.event_id else None,
                    "integrity_hash": ev.integrity_hash,
                },
            )
        )

    # 4. Fetch underlying SecurityEvents from detections and evidence
    all_event_uuids = set(event_ids_from_evidence)
    for d in detection_map.values():
        for eid in d.event_ids or []:
            try:
                all_event_uuids.add(uuid.UUID(eid))
            except ValueError:
                continue

    if all_event_uuids:
        evt_stmt = select(SecurityEvent).where(
            SecurityEvent.tenant_id == tenant_id,
            SecurityEvent.id.in_(list(all_event_uuids)),
        )
        evt_res = await db.execute(evt_stmt)
        for e in evt_res.scalars().all():
            timeline.append(
                TimelineItem(
                    timestamp=e.timestamp,
                    item_type="SECURITY_EVENT",
                    id=str(e.id),
                    title=f"Event: {e.event_type} via {e.source}",
                    description=f"Security event from {e.source_ip or 'unknown-ip'} (user: {e.username or 'unknown'})",
                    severity=e.severity,
                    source=e.source,
                    mitre_techniques=[],
                    metadata={
                        "source_ip": e.source_ip,
                        "username": e.username,
                        "hostname": e.hostname,
                        "raw_summary": str(e.raw_event)[:150] if e.raw_event else "",
                    },
                )
            )

    # Sort timeline chronologically
    from app.correlation.incident_builder import ensure_utc

    timeline.sort(key=lambda item: ensure_utc(item.timestamp))
    return timeline
