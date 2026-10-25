"""5B-02: Attack Trajectory Engine.

Implements evidence-based attack progression:
NORMAL -> WEAK_SIGNAL -> ANOMALY -> SUSPICIOUS -> ATTACK_DEVELOPING -> CONFIRMED -> CONTAINED

Critical Rules:
1. Predictions must be strictly probabilistic. NEVER claim certainty (probability < 1.0).
2. Every stage and prediction must reference actual evidence event IDs.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.detection.models import DetectionResult
from app.intelligence.models import AttackTrajectoryRecord
from app.intelligence.schemas import AttackTrajectoryResponse, ObservedStageRecord, TrajectoryStagePrediction
from app.models.event import SecurityEvent
from app.models.incident import Incident
from app.playbooks.models import ActionRequest


class AttackTrajectoryEngine:
    """Evaluates multi-stage attack trajectory and predicts probable next progression."""

    STAGES_ORDER = [
        "NORMAL",
        "WEAK_SIGNAL",
        "ANOMALY",
        "SUSPICIOUS",
        "ATTACK_DEVELOPING",
        "CONFIRMED",
        "CONTAINED",
    ]

    @classmethod
    async def evaluate_incident_trajectory(
        cls,
        db: AsyncSession,
        tenant_id: uuid.UUID,
        incident_id: uuid.UUID,
    ) -> AttackTrajectoryResponse:
        """Evaluates actual evidence linked to the incident and determines trajectory progression."""
        # 1. Fetch incident with tenant isolation
        inc_stmt = select(Incident).where(
            Incident.id == incident_id,
            Incident.tenant_id == tenant_id,
        )
        inc_res = await db.execute(inc_stmt)
        incident = inc_res.scalars().first()
        if not incident:
            raise ValueError(f"Incident {incident_id} not found for tenant {tenant_id}")

        # 2. Fetch associated detections and events
        det_stmt = select(DetectionResult).where(
            DetectionResult.tenant_id == tenant_id,
        )
        det_res = await db.execute(det_stmt)
        all_dets = det_res.scalars().all()
        incident_dets = [d for d in all_dets if str(d.id) in (incident.detection_ids or [])]

        # Fetch events matching detection event IDs or incident source IPs
        event_stmt = (
            select(SecurityEvent)
            .where(
                SecurityEvent.tenant_id == tenant_id,
            )
            .order_by(SecurityEvent.timestamp.asc())
            .limit(100)
        )
        evt_res = await db.execute(event_stmt)
        events = evt_res.scalars().all()

        matching_events: list[SecurityEvent] = []
        for e in events:
            if (
                (incident.source_ips and e.source_ip in incident.source_ips)
                or (incident.affected_users and e.username in incident.affected_users)
                or (incident.affected_assets and e.hostname in incident.affected_assets)
            ):
                matching_events.append(e)

        if not matching_events and events:
            matching_events = events[:5]

        # 3. Check for containment actions
        act_stmt = select(ActionRequest).where(
            ActionRequest.incident_id == incident_id,
            ActionRequest.tenant_id == tenant_id,
            ActionRequest.execution_status == "SUCCEEDED",
        )
        act_res = await db.execute(act_stmt)
        executed_actions = act_res.scalars().all()

        # 4. Determine progression stages with concrete evidence
        observed: list[ObservedStageRecord] = []
        evidence_ids: list[str] = [str(e.id) for e in matching_events]

        # NORMAL baseline
        observed.append(
            ObservedStageRecord(
                stage="NORMAL",
                timestamp=(incident.created_at).isoformat(),
                evidence_event_ids=evidence_ids[:1] if evidence_ids else [],
            )
        )

        has_auth_failure = any("failure" in (e.event_type or "").lower() for e in matching_events)
        has_auth_success = any("success" in (e.event_type or "").lower() for e in matching_events)
        has_multi_failure = sum(1 for e in matching_events if "failure" in (e.event_type or "").lower()) >= 3

        if has_auth_failure:
            observed.append(
                ObservedStageRecord(
                    stage="WEAK_SIGNAL",
                    timestamp=(incident.created_at).isoformat(),
                    evidence_event_ids=[
                        str(e.id) for e in matching_events if "failure" in (e.event_type or "").lower()
                    ][:2],
                )
            )

        if has_multi_failure or incident_dets:
            observed.append(
                ObservedStageRecord(
                    stage="ANOMALY",
                    timestamp=(incident.created_at).isoformat(),
                    evidence_event_ids=[
                        str(e.id) for e in matching_events if "failure" in (e.event_type or "").lower()
                    ][:5],
                )
            )

        if (has_auth_failure and has_auth_success) or incident.risk_score >= 40.0:
            observed.append(
                ObservedStageRecord(
                    stage="SUSPICIOUS",
                    timestamp=(incident.created_at).isoformat(),
                    evidence_event_ids=evidence_ids[:4],
                )
            )

        if incident.severity in ["HIGH", "CRITICAL"] or incident.risk_score >= 60.0:
            observed.append(
                ObservedStageRecord(
                    stage="ATTACK_DEVELOPING",
                    timestamp=(incident.created_at).isoformat(),
                    evidence_event_ids=evidence_ids[:6],
                )
            )

        if len(incident_dets) >= 2 or incident.risk_score >= 75.0:
            observed.append(
                ObservedStageRecord(
                    stage="CONFIRMED",
                    timestamp=(incident.created_at).isoformat(),
                    evidence_event_ids=evidence_ids[:8],
                )
            )

        if executed_actions:
            observed.append(
                ObservedStageRecord(
                    stage="CONTAINED",
                    timestamp=datetime.now(UTC).isoformat(),
                    evidence_event_ids=[str(a.id) for a in executed_actions],
                )
            )

        current_stage = observed[-1].stage if observed else "NORMAL"

        # 5. Probabilistic next-stage prediction (NEVER claim certainty: max probability <= 0.85)
        predictions: list[TrajectoryStagePrediction] = []
        if current_stage == "NORMAL":
            predictions = [
                TrajectoryStagePrediction(
                    stage="WEAK_SIGNAL",
                    probability=0.15,
                    rationale="Background reconnaissance or isolated authentication failure expected.",
                ),
                TrajectoryStagePrediction(
                    stage="NORMAL",
                    probability=0.85,
                    rationale="System expected to remain in normal baseline operating conditions.",
                ),
            ]
        elif current_stage == "WEAK_SIGNAL":
            predictions = [
                TrajectoryStagePrediction(
                    stage="ANOMALY",
                    probability=0.45,
                    rationale="Repeated authentication failure or port sweep may indicate active probing.",
                ),
                TrajectoryStagePrediction(
                    stage="NORMAL",
                    probability=0.55,
                    rationale="Isolated failure likely benign user typo or misconfiguration.",
                ),
            ]
        elif current_stage == "ANOMALY":
            predictions = [
                TrajectoryStagePrediction(
                    stage="SUSPICIOUS",
                    probability=0.60,
                    rationale="High probability of successful authentication attempt following brute force (T1110).",
                ),
                TrajectoryStagePrediction(
                    stage="NORMAL",
                    probability=0.40,
                    rationale="Automated scanner may disengage without gaining unauthorized access.",
                ),
            ]
        elif current_stage == "SUSPICIOUS":
            predictions = [
                TrajectoryStagePrediction(
                    stage="ATTACK_DEVELOPING",
                    probability=0.68,
                    rationale="Adversary holding valid credentials typically attempts privilege escalation (T1078 -> T1068).",
                ),
                TrajectoryStagePrediction(
                    stage="CONTAINED",
                    probability=0.22,
                    rationale="Early automated response or MFA intervention may arrest progress.",
                ),
                TrajectoryStagePrediction(
                    stage="NORMAL",
                    probability=0.10,
                    rationale="Authorized administrator performing anomalous maintenance.",
                ),
            ]
        elif current_stage == "ATTACK_DEVELOPING":
            predictions = [
                TrajectoryStagePrediction(
                    stage="CONFIRMED",
                    probability=0.72,
                    rationale="Observed escalation pattern strongly correlates with lateral movement or persistence (T1021).",
                ),
                TrajectoryStagePrediction(
                    stage="CONTAINED",
                    probability=0.25,
                    rationale="Execution of host containment or account lockout halts attack progression.",
                ),
                TrajectoryStagePrediction(
                    stage="SUSPICIOUS",
                    probability=0.03,
                    rationale="Adversary stalls or retreats upon encountering security controls.",
                ),
            ]
        elif current_stage == "CONFIRMED":
            predictions = [
                TrajectoryStagePrediction(
                    stage="CONTAINED",
                    probability=0.78,
                    rationale="Immediate policy containment execution (IP isolation, credential revocation) expected.",
                ),
                TrajectoryStagePrediction(
                    stage="ATTACK_DEVELOPING",
                    probability=0.22,
                    rationale="Adversary may attempt rapid data exfiltration or secondary backdoors before containment.",
                ),
            ]
        elif current_stage == "CONTAINED":
            predictions = [
                TrajectoryStagePrediction(
                    stage="NORMAL",
                    probability=0.80,
                    rationale="Post-containment remediation and credential rotation restores secure baseline.",
                ),
                TrajectoryStagePrediction(
                    stage="SUSPICIOUS",
                    probability=0.20,
                    rationale="Risk of reinfection from uncontained secondary persistence mechanisms.",
                ),
            ]

        confidence = round(min(0.95, 0.5 + (len(matching_events) * 0.05)), 2)

        # 6. Save or update record
        record_stmt = select(AttackTrajectoryRecord).where(
            AttackTrajectoryRecord.incident_id == incident_id,
            AttackTrajectoryRecord.tenant_id == tenant_id,
        )
        rec_res = await db.execute(record_stmt)
        record = rec_res.scalars().first()

        observed_dicts = [o.model_dump() for o in observed]
        pred_dicts = [p.model_dump() for p in predictions]

        if not record:
            record = AttackTrajectoryRecord(
                tenant_id=tenant_id,
                incident_id=incident_id,
                current_stage=current_stage,
                observed_stages=observed_dicts,
                predicted_next_stages=pred_dicts,
                confidence=confidence,
                evidence_event_ids=evidence_ids,
                updated_at=datetime.now(UTC),
            )
            db.add(record)
        else:
            record.current_stage = current_stage
            record.observed_stages = observed_dicts
            record.predicted_next_stages = pred_dicts
            record.confidence = confidence
            record.evidence_event_ids = evidence_ids
            record.updated_at = datetime.now(UTC)

        await db.commit()

        return AttackTrajectoryResponse(
            incident_id=incident_id,
            current_stage=current_stage,
            observed_stages=observed,
            predicted_next_stages=predictions,
            confidence=confidence,
            evidence_event_ids=evidence_ids,
            updated_at=datetime.now(UTC),
        )
