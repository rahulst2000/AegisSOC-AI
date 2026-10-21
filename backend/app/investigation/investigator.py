import uuid

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.ai.gateway import get_ai_provider
from app.detection.models import DetectionResult
from app.investigation.confidence import calculate_investigation_confidence
from app.investigation.evidence_collector import EvidenceCollector
from app.investigation.evidence_validator import EvidenceValidator
from app.investigation.models import Investigation, InvestigationFinding, InvestigationHypothesis
from app.models.event import SecurityEvent
from app.models.evidence import Evidence
from app.models.incident import Incident
from app.services.audit_service import log_audit_event


async def run_investigation(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
    force_refresh: bool = False,
    analyst_notes: str | None = None,
    user_id: uuid.UUID | None = None,
) -> Investigation:
    """
    Executes a forensic AI-assisted investigation on an Incident:
    1. Collects context via EvidenceCollector (tenant-scoped).
    2. Runs AI provider (with prompt injection defense).
    3. Validates findings & evidence hashes via EvidenceValidator.
    4. Computes deterministic confidence.
    5. Persists Investigation, Hypotheses, and Findings.
    6. Logs audit events.
    """
    # 1. Fetch incident with tenant authorization
    stmt = select(Incident).where(
        Incident.id == incident_id,
        Incident.tenant_id == tenant_id,
    )
    res = await db.execute(stmt)
    incident = res.scalars().first()
    if not incident:
        raise ValueError(f"Incident {incident_id} not found for tenant {tenant_id}")

    # Check existing investigation if not forced refresh
    if not force_refresh:
        inv_stmt = (
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
        existing_res = await db.execute(inv_stmt)
        existing_inv = existing_res.scalars().first()
        if existing_inv:
            return existing_inv

    # 2. Gather context using read-only EvidenceCollector
    collector = EvidenceCollector(db, tenant_id)
    validator = EvidenceValidator(db, tenant_id)

    # Collect detections
    det_ids_raw = incident.detection_ids or []
    det_uuids: list[uuid.UUID] = []
    for d in det_ids_raw:
        try:
            det_uuids.append(uuid.UUID(str(d)))
        except ValueError:
            pass

    detections: list[DetectionResult] = []
    if det_uuids:
        det_stmt = select(DetectionResult).where(
            DetectionResult.id.in_(det_uuids),
            DetectionResult.tenant_id == tenant_id,
        )
        det_res = await db.execute(det_stmt)
        detections = list(det_res.scalars().all())

    # Extract all event IDs across detections
    event_ids_set: set[str] = set()
    for d in detections:
        for eid in d.event_ids or []:
            event_ids_set.add(str(eid))

    # Also collect from Evidence linked to this incident
    ev_stmt = select(Evidence.event_id).where(
        Evidence.incident_id == incident.id,
        Evidence.tenant_id == tenant_id,
        Evidence.event_id.isnot(None),
    )
    ev_res = await db.execute(ev_stmt)
    for row in ev_res.scalars().all():
        if row:
            event_ids_set.add(str(row))

    # If still empty, collect matching events by affected users and source IPs
    if not event_ids_set:
        conditions = []
        if incident.affected_users:
            conditions.append(SecurityEvent.username.in_(incident.affected_users))
        if incident.source_ips:
            conditions.append(SecurityEvent.source_ip.in_(incident.source_ips))
        if conditions:
            from sqlalchemy import or_

            fallback_evt_stmt = (
                select(SecurityEvent.id)
                .where(SecurityEvent.tenant_id == tenant_id, or_(*conditions))
                .order_by(SecurityEvent.timestamp.desc())
                .limit(50)
            )
            fallback_res = await db.execute(fallback_evt_stmt)
            for row in fallback_res.scalars().all():
                if row:
                    event_ids_set.add(str(row))

    # Fetch SecurityEvents
    events: list[SecurityEvent] = []
    if event_ids_set:
        event_uuids = [uuid.UUID(eid) for eid in event_ids_set]
        evt_stmt = (
            select(SecurityEvent)
            .where(
                SecurityEvent.id.in_(event_uuids),
                SecurityEvent.tenant_id == tenant_id,
            )
            .order_by(SecurityEvent.timestamp.asc())
        )
        evt_res = await db.execute(evt_stmt)
        events = list(evt_res.scalars().all())

    # Ensure immutable Evidence records exist for contextual events
    if events:
        from app.detection.evidence import link_event_evidence

        existing_ev_stmt = select(Evidence.event_id).where(
            Evidence.event_id.in_([e.id for e in events]),
            Evidence.tenant_id == tenant_id,
        )
        existing_ev_res = await db.execute(existing_ev_stmt)
        covered_eids = set(existing_ev_res.scalars().all())
        for e in events:
            if e.id not in covered_eids:
                await link_event_evidence(
                    db=db,
                    tenant_id=tenant_id,
                    event=e,
                    description=f"Evidence collected for incident: {incident.title}",
                    incident_id=incident.id,
                )

    # Fetch timeline
    timeline = await collector.get_incident_timeline(incident_id)

    # Build context dictionary
    context = {
        "incident": {
            "id": str(incident.id),
            "title": incident.title,
            "description": incident.description,
            "severity": incident.severity,
            "risk_score": incident.risk_score,
            "confidence_score": incident.confidence,
            "mitre_techniques": incident.mitre_techniques or [],
            "affected_assets": incident.affected_assets or [],
            "affected_users": incident.affected_users or [],
            "source_ips": incident.source_ips or [],
        },
        "detections": [
            {
                "id": str(d.id),
                "rule_id": d.rule_id,
                "title": d.title,
                "severity": d.severity,
                "confidence": d.confidence,
                "mitre_techniques": d.mitre_techniques or [],
                "event_ids": d.event_ids or [],
            }
            for d in detections
        ],
        "events": [
            {
                "id": str(e.id),
                "event_type": e.event_type,
                "timestamp": e.timestamp.isoformat(),
                "source_ip": e.source_ip,
                "destination_ip": (
                    e.normalized_event.get("destination", {}).get("ip")
                    if isinstance(e.normalized_event, dict)
                    else None
                ),
                "user_name": e.username,
                "hostname": e.hostname,
                "severity": e.severity,
                "raw_payload": e.raw_event,
                "normalized_event": e.normalized_event,
            }
            for e in events
        ],
        "timeline": timeline,
        "analyst_notes": analyst_notes,
    }

    # 3. AI Provider Analysis
    ai_provider = get_ai_provider()
    raw_ai_result = await ai_provider.analyze(context)

    # 4. Forensic Evidence Validation
    validated_findings = await validator.validate_findings(raw_ai_result.findings)
    validated_hypotheses = await validator.validate_hypotheses(raw_ai_result.hypotheses)

    # 5. Deterministic Confidence Calculation
    rule_confs = [d.confidence for d in detections if d.confidence is not None]
    verified_eids = {eid for f in validated_findings for eid in f.evidence_ids if f.status in ("CONFIRMED", "LIKELY")}
    contradicting_count = sum(len(h.contradicting_evidence) for h in validated_hypotheses if h.status == "DISPROVED")
    unknowns_count = len(raw_ai_result.unknowns)

    computed_confidence = calculate_investigation_confidence(
        base_rule_confidences=rule_confs,
        verified_evidence_count=len(verified_eids),
        independent_signal_count=len(detections),
        contradicting_evidence_count=contradicting_count,
        unknowns_count=unknowns_count,
    )

    # 6. Delete previous investigation records if force_refresh is True
    del_stmt = delete(Investigation).where(
        Investigation.incident_id == incident_id,
        Investigation.tenant_id == tenant_id,
    )
    await db.execute(del_stmt)

    # 7. Persist Investigation
    investigation = Investigation(
        incident_id=incident_id,
        tenant_id=tenant_id,
        status="COMPLETED",
        executive_summary=raw_ai_result.executive_summary,
        attack_chain=raw_ai_result.attack_chain,
        known_facts=raw_ai_result.known_facts,
        unknowns=raw_ai_result.unknowns,
        recommended_next_steps=raw_ai_result.recommended_next_steps,
        l1_decision=raw_ai_result.l1_decision,
        l2_escalation_recommended=raw_ai_result.l2_escalation_recommended,
        risk_score=incident.risk_score,
        confidence_score=computed_confidence,
    )
    db.add(investigation)
    await db.flush()

    # Persist Hypotheses
    for hyp in validated_hypotheses:
        db_hyp = InvestigationHypothesis(
            investigation_id=investigation.id,
            tenant_id=tenant_id,
            hypothesis_id=hyp.hypothesis_id,
            title=hyp.title,
            description=hyp.description,
            status=hyp.status,
            confidence=hyp.confidence,
            evidence_ids=hyp.evidence_ids,
            supporting_evidence=hyp.supporting_evidence,
            contradicting_evidence=hyp.contradicting_evidence,
            unknowns=hyp.unknowns,
        )
        db.add(db_hyp)

    # Persist Findings
    for find in validated_findings:
        db_find = InvestigationFinding(
            investigation_id=investigation.id,
            tenant_id=tenant_id,
            finding=find.finding,
            status=find.status,
            evidence_ids=find.evidence_ids,
            confidence=find.confidence,
            reasoning_summary=find.reasoning_summary,
        )
        db.add(db_find)

    await db.flush()

    # 8. Log Audit Events
    await log_audit_event(
        db=db,
        tenant_id=tenant_id,
        user_id=user_id,
        action="INVESTIGATION_STARTED",
        resource_type="investigation",
        resource_id=str(investigation.id),
        result="SUCCESS",
        metadata={
            "incident_id": str(incident_id),
            "findings_count": len(validated_findings),
            "hypotheses_count": len(validated_hypotheses),
            "confidence_score": computed_confidence,
        },
    )

    # Eagerly reload relationships
    final_stmt = (
        select(Investigation)
        .where(Investigation.id == investigation.id)
        .options(
            selectinload(Investigation.hypotheses),
            selectinload(Investigation.findings),
        )
    )
    res_final = await db.execute(final_stmt)
    return res_final.scalars().first() or investigation
