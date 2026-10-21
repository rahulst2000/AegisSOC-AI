import logging
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.detection.models import DetectionResult
from app.models.event import SecurityEvent
from app.models.evidence import Evidence
from app.models.incident import Incident

logger = logging.getLogger(__name__)


def calculate_risk_score(
    severity: str,
    mitre_techniques: list[str],
    affected_assets: list[str],
    affected_users: list[str],
) -> float:
    """
    Deterministic calculation of potential security impact (Risk).
    Distinct from Confidence (certainty of evidence).
    Yields bounded score in [0.0, 100.0].
    """
    severity_map = {
        "CRITICAL": 85.0,
        "HIGH": 70.0,
        "MEDIUM": 45.0,
        "LOW": 20.0,
    }
    base = severity_map.get(severity.upper(), 30.0)

    # Amplification based on attacker breadth
    technique_bonus = min(15.0, len(set(mitre_techniques)) * 4.0)
    asset_bonus = 5.0 if len(set(affected_assets)) > 1 else 0.0
    user_bonus = 5.0 if len(set(affected_users)) > 1 else 0.0

    total_risk = base + technique_bonus + asset_bonus + user_bonus
    return min(100.0, max(0.0, round(total_risk, 1)))


def calculate_confidence_score(
    detections: list[DetectionResult],
    evidence_count: int,
) -> float:
    """
    Deterministic calculation of evidentiary certainty (Confidence).
    Synthesizes rule confidence metrics with verifiable forensic depth.
    Yields bounded score in [0.0, 1.0].
    """
    if not detections:
        return 0.5

    mean_detection_conf = sum(d.confidence for d in detections) / len(detections)
    evidence_factor = min(1.0, 0.75 + 0.03 * min(evidence_count, 8))

    composite = (mean_detection_conf * 0.7) + (evidence_factor * 0.3)
    return min(1.0, max(0.1, round(composite, 2)))


def ensure_utc(dt: datetime | None) -> datetime:
    if dt is None:
        return datetime.now(UTC)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


async def build_or_update_incident(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    detections: list[DetectionResult],
    events: list[SecurityEvent],
    correlation_window_minutes: int = 15,
) -> Incident:
    """
    Creates a new incident or aggregates into an existing active incident within the correlation window.
    Strictly isolated to tenant_id.
    """
    if not detections:
        raise ValueError("Cannot construct incident without at least one detection result.")

    # Invariant: All detections and events must belong strictly to tenant_id
    for d in detections:
        if d.tenant_id != tenant_id:
            raise ValueError(f"Cross-tenant detection violation: Detection {d.id} tenant != {tenant_id}")
    for e in events:
        if e.tenant_id != tenant_id:
            raise ValueError(f"Cross-tenant event violation: Event {e.id} tenant != {tenant_id}")

    # Gather entity dimensions
    detection_ids = [str(d.id) for d in detections]
    source_ips = sorted({e.source_ip for e in events if e.source_ip})
    usernames = sorted({e.username for e in events if e.username})
    hostnames = sorted({e.hostname for e in events if e.hostname})

    all_mitre_techniques = sorted({t for d in detections for t in (d.mitre_techniques or [])})

    # Highest severity among detections
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    highest_severity = max(
        (d.severity.upper() for d in detections),
        key=lambda s: severity_order.get(s, 0),
        default="MEDIUM",
    )

    timestamps = [ensure_utc(e.timestamp) for e in events] + [ensure_utc(d.timestamp) for d in detections]
    first_seen = min(timestamps) if timestamps else datetime.now(UTC)
    last_seen = max(timestamps) if timestamps else datetime.now(UTC)

    # Look for existing OPEN / INVESTIGATING incident for this tenant within correlation window
    cutoff = first_seen - timedelta(minutes=correlation_window_minutes)

    candidate_stmt = (
        select(Incident)
        .where(
            Incident.tenant_id == tenant_id,
            Incident.status.in_(["OPEN", "INVESTIGATING"]),
            Incident.last_seen >= cutoff,
        )
        .order_by(Incident.last_seen.desc())
    )
    res = await db.execute(candidate_stmt)
    existing_incidents = list(res.scalars().all())

    target_incident: Incident | None = None
    for cand in existing_incidents:
        # Check entity overlap (source_ip, username, or hostname)
        cand_ips = set(cand.source_ips or [])
        cand_users = set(cand.affected_users or [])
        cand_hosts = set(cand.affected_assets or [])

        if (
            (source_ips and cand_ips.intersection(source_ips))
            or (usernames and cand_users.intersection(usernames))
            or (hostnames and cand_hosts.intersection(hostnames))
        ):
            target_incident = cand
            break

    # Extract all event IDs for evidence linking
    all_event_ids = [e.id for e in events]

    if target_incident:
        # Update existing incident
        merged_det_ids = sorted(set((target_incident.detection_ids or []) + detection_ids))
        merged_techniques = sorted(set((target_incident.mitre_techniques or []) + all_mitre_techniques))
        merged_assets = sorted(set((target_incident.affected_assets or []) + hostnames))
        merged_users = sorted(set((target_incident.affected_users or []) + usernames))
        merged_ips = sorted(set((target_incident.source_ips or []) + source_ips))

        # Promote severity if new detection is higher
        if severity_order.get(highest_severity, 0) > severity_order.get(target_incident.severity, 0):
            target_incident.severity = highest_severity

        target_incident.detection_ids = merged_det_ids
        target_incident.mitre_techniques = merged_techniques
        target_incident.affected_assets = merged_assets
        target_incident.affected_users = merged_users
        target_incident.source_ips = merged_ips
        target_incident.last_seen = max(ensure_utc(target_incident.last_seen), ensure_utc(last_seen))

        # Recalculate deterministic metrics
        target_incident.risk_score = calculate_risk_score(
            severity=target_incident.severity,
            mitre_techniques=merged_techniques,
            affected_assets=merged_assets,
            affected_users=merged_users,
        )
        target_incident.confidence = calculate_confidence_score(
            detections=detections,
            evidence_count=len(all_event_ids),
        )
        target_incident.updated_at = datetime.now(UTC)
        incident = target_incident
        logger.info(f"Updated existing incident {incident.id} with {len(detections)} new detections")
    else:
        # Generate descriptive title
        primary_title = detections[0].title
        if len(detections) > 1:
            title = f"Correlated Multi-Signal Attack: {primary_title} (+{len(detections) - 1} signals)"
        else:
            title = f"Security Incident: {primary_title}"

        tech_summary = ", ".join(all_mitre_techniques) or "None"
        description = (
            f"Correlated security incident derived from {len(detections)} detection(s) "
            f"involving {len(events)} security events. Attributed MITRE techniques: {tech_summary}."
        )

        risk_score = calculate_risk_score(
            severity=highest_severity,
            mitre_techniques=all_mitre_techniques,
            affected_assets=hostnames,
            affected_users=usernames,
        )
        confidence = calculate_confidence_score(
            detections=detections,
            evidence_count=len(all_event_ids),
        )

        incident = Incident(
            tenant_id=tenant_id,
            title=title,
            description=description,
            severity=highest_severity,
            risk_score=risk_score,
            confidence=confidence,
            status="OPEN",
            mitre_techniques=all_mitre_techniques,
            detection_ids=detection_ids,
            affected_assets=hostnames,
            affected_users=usernames,
            source_ips=source_ips,
            first_seen=first_seen,
            last_seen=last_seen,
        )
        db.add(incident)
        await db.flush()
        logger.info(f"Created new incident {incident.id} (tenant={tenant_id}, risk={risk_score})")

    # Link Evidence items from these events to the Incident
    if all_event_ids:
        evidence_stmt = select(Evidence).where(
            Evidence.tenant_id == tenant_id,
            Evidence.event_id.in_(all_event_ids),
            Evidence.incident_id.is_(None),
        )
        ev_res = await db.execute(evidence_stmt)
        unlinked_evidence = list(ev_res.scalars().all())
        for ev in unlinked_evidence:
            ev.incident_id = incident.id

    await db.commit()
    await db.refresh(incident)
    return incident
