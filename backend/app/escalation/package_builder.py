import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.investigation.models import Investigation
from app.models.incident import Incident
from app.playbooks.models import ActionRequest


async def build_l2_investigation_package(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
    reason: str,
    urgency: str = "HIGH",
) -> dict[str, Any]:
    """
    Builds the authoritative Tier-2 SOC investigation package.
    Consolidates why escalated, known facts, unknowns, evidence IDs, timeline,
    prior actions, verification results, and recommendations.
    """
    # 1. Fetch incident
    inc_stmt = select(Incident).where(Incident.id == incident_id, Incident.tenant_id == tenant_id)
    inc_res = await db.execute(inc_stmt)
    incident = inc_res.scalars().first()
    if not incident:
        raise ValueError(f"Incident {incident_id} not found for tenant {tenant_id}")

    # 2. Fetch investigation if available
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
    inv_res = await db.execute(inv_stmt)
    investigation = inv_res.scalars().first()

    # 3. Fetch actions taken so far
    act_stmt = (
        select(ActionRequest)
        .where(
            ActionRequest.incident_id == incident_id,
            ActionRequest.tenant_id == tenant_id,
        )
        .order_by(ActionRequest.requested_at.asc())
    )
    act_res = await db.execute(act_stmt)
    actions = act_res.scalars().all()

    # 4. Fetch timeline
    from app.investigation.evidence_collector import EvidenceCollector

    collector = EvidenceCollector(db, tenant_id)
    timeline = await collector.get_incident_timeline(incident_id)

    # 5. Assemble structured package
    known_facts: list[str] = []
    unknowns: list[str] = []
    hypotheses_summary: list[dict[str, Any]] = []
    findings_summary: list[dict[str, Any]] = []

    if investigation:
        known_facts = list(investigation.known_facts)
        unknowns = list(investigation.unknowns)
        hypotheses_summary = [
            {
                "id": h.hypothesis_id,
                "title": h.title,
                "status": h.status,
                "confidence": h.confidence,
                "supporting_evidence": h.supporting_evidence,
                "unknowns": h.unknowns,
            }
            for h in investigation.hypotheses
        ]
        findings_summary = [
            {
                "finding": f.finding,
                "status": f.status,
                "confidence": f.confidence,
                "evidence_ids": f.evidence_ids,
            }
            for f in investigation.findings
        ]

    prior_actions_summary = [
        {
            "action_id": str(a.id),
            "action_type": a.action_type,
            "target": a.target_entity,
            "approval_status": a.approval_status,
            "execution_status": a.execution_status,
            "verification_status": a.verification_status,
            "error": a.error,
        }
        for a in actions
    ]

    return {
        "incident_id": str(incident.id),
        "title": incident.title,
        "urgency": urgency,
        "why_escalated": reason,
        "risk_score": incident.risk_score,
        "confidence_score": investigation.confidence_score if investigation else incident.confidence,
        "mitre_techniques": incident.mitre_techniques or [],
        "affected_assets": incident.affected_assets or [],
        "affected_users": incident.affected_users or [],
        "source_ips": incident.source_ips or [],
        "what_is_known": known_facts,
        "what_is_unknown": unknowns,
        "hypotheses": hypotheses_summary,
        "findings": findings_summary,
        "timeline": timeline,
        "actions_already_taken": prior_actions_summary,
        "recommended_next_investigation": (
            investigation.recommended_next_steps
            if investigation and investigation.recommended_next_steps
            else [
                "Perform memory acquisition on affected hosts",
                "Review perimeter proxy logs for C2 beaconing",
                "Execute credential audit across targeted identity directory",
            ]
        ),
    }
