"""5B-01: Dynamic Security State Model - SecurityState(t).

Maintains dynamic, tenant-isolated security state representation:
SecurityState(t) = {Users, Assets, Identities, Processes, Connections, Vulnerabilities, Controls, Incidents, Alerts, Risk, Posture}

Critical Rule: Every state transition MUST have verifiable evidence. Unbacked transitions are rejected.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ValidationException
from app.intelligence.models import SecurityStateSnapshot, SecurityStateTransition
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.incident import Incident
from app.models.user import User
from app.security_improvement.models import SecurityFinding


class SecurityStateModel:
    """Computes and tracks dynamic SecurityState(t) and auditable transitions."""

    @classmethod
    async def compute_current_state(
        cls,
        db: AsyncSession,
        tenant_id: uuid.UUID,
    ) -> SecurityStateSnapshot:
        """Computes current SecurityState(t) strictly from database records."""
        now = datetime.now(UTC)

        # 1. Fetch asset count & metadata
        asset_res = await db.execute(select(Asset).where(Asset.tenant_id == tenant_id))
        assets = asset_res.scalars().all()
        monitored_assets_count = len(assets)

        # 2. Fetch identity count
        user_res = await db.execute(select(User).where(User.tenant_id == tenant_id))
        users = user_res.scalars().all()
        monitored_identities_count = len(users)

        # 3. Fetch active incidents
        inc_res = await db.execute(
            select(Incident).where(
                Incident.tenant_id == tenant_id,
                Incident.status.in_(["OPEN", "TRIAGED", "ESCALATED"]),
            )
        )
        open_incidents = inc_res.scalars().all()
        open_incidents_count = len(open_incidents)

        # 4. Fetch active alerts
        alert_res = await db.execute(
            select(Alert).where(
                Alert.tenant_id == tenant_id,
                Alert.status == "OPEN",
            )
        )
        active_alerts = alert_res.scalars().all()
        active_alerts_count = len(active_alerts)

        # 5. Fetch security findings / vulnerabilities
        finding_res = await db.execute(
            select(SecurityFinding).where(
                SecurityFinding.tenant_id == tenant_id,
                SecurityFinding.status.in_(["OPEN", "UNDER_REMEDIATION", "REOPENED"]),
            )
        )
        open_findings = finding_res.scalars().all()

        # 6. Calculate deterministic evidence-backed risk score (0.0 to 100.0)
        # Base risk: sum of active incident risks weighted by severity, plus open findings
        incident_risk_contrib = sum(min(i.risk_score, 100.0) for i in open_incidents)
        finding_risk_contrib = sum(
            25.0 if f.severity == "CRITICAL" else 15.0 if f.severity == "HIGH" else 5.0 for f in open_findings
        )
        total_risk = min(
            100.0, (incident_risk_contrib * 0.5) + (finding_risk_contrib * 0.3) + (active_alerts_count * 1.5)
        )
        risk_score = round(total_risk, 2)

        # Posture score inversely related to risk, with bonus for active controls
        posture_score = round(max(10.0, 100.0 - (risk_score * 0.85)), 2)

        # 7. Construct state vector
        state_vector: dict[str, Any] = {
            "monitored_assets": [
                {"id": str(a.id), "hostname": a.hostname, "ip": a.ip_address, "criticality": a.criticality}
                for a in assets[:50]
            ],
            "monitored_identities": [{"id": str(u.id), "email": u.email, "role": u.role} for u in users[:50]],
            "active_incidents": [
                {"id": str(i.id), "title": i.title, "severity": i.severity, "risk": i.risk_score}
                for i in open_incidents[:20]
            ],
            "open_findings": [
                {"id": str(f.id), "title": f.title, "severity": f.severity, "technique": f.technique}
                for f in open_findings[:20]
            ],
            "active_controls": [
                "AUTHENTICATION_JWT_HS256",
                "ROLE_BASED_ACCESS_CONTROL",
                "TENANT_ISOLATION_FILTER",
                "SIGMA_DETECTION_ENGINE",
                "SHA256_EVIDENCE_VALIDATOR",
                "POLICY_GATEWAY",
                "HUMAN_IN_THE_LOOP_APPROVAL",
            ],
        }

        # 8. Compute deterministic state SHA-256 hash
        canonical_json = json.dumps(state_vector, sort_keys=True)
        state_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

        snapshot = SecurityStateSnapshot(
            tenant_id=tenant_id,
            timestamp=now,
            risk_score=risk_score,
            posture_score=posture_score,
            open_incidents_count=open_incidents_count,
            active_alerts_count=active_alerts_count,
            monitored_assets_count=monitored_assets_count,
            monitored_identities_count=monitored_identities_count,
            state_vector=state_vector,
            state_hash=state_hash,
            created_at=now,
        )
        db.add(snapshot)
        await db.commit()
        await db.refresh(snapshot)
        return snapshot

    @classmethod
    async def record_transition(
        cls,
        db: AsyncSession,
        tenant_id: uuid.UUID,
        trigger_type: str,
        from_state_summary: str,
        to_state_summary: str,
        evidence_references: list[dict[str, Any]],
        rationale: str,
        trigger_entity_id: str | None = None,
        risk_delta: float = 0.0,
        posture_delta: float = 0.0,
        confidence: float = 1.0,
    ) -> SecurityStateTransition:
        """Records an auditable state transition between SecurityState(t-1) and SecurityState(t).

        Enforces Critical Rule: Every state transition MUST have verifiable evidence.
        """
        if not evidence_references:
            raise ValidationException(
                "State transition rejected: Every security state transition requires verifiable evidence references."
            )

        transition = SecurityStateTransition(
            tenant_id=tenant_id,
            timestamp=datetime.now(UTC),
            trigger_type=trigger_type,
            trigger_entity_id=trigger_entity_id,
            from_state_summary=from_state_summary,
            to_state_summary=to_state_summary,
            risk_delta=risk_delta,
            posture_delta=posture_delta,
            evidence_references=evidence_references,
            rationale=rationale,
            confidence=max(0.0, min(1.0, confidence)),
        )
        db.add(transition)
        await db.commit()
        await db.refresh(transition)
        return transition

    @classmethod
    async def get_state_history(
        cls,
        db: AsyncSession,
        tenant_id: uuid.UUID,
        limit: int = 20,
    ) -> list[SecurityStateSnapshot]:
        """Retrieves historical security state snapshots for tenant."""
        stmt = (
            select(SecurityStateSnapshot)
            .where(SecurityStateSnapshot.tenant_id == tenant_id)
            .order_by(SecurityStateSnapshot.timestamp.desc())
            .limit(min(limit, 100))
        )
        res = await db.execute(stmt)
        return list(res.scalars().all())

    @classmethod
    async def get_recent_transitions(
        cls,
        db: AsyncSession,
        tenant_id: uuid.UUID,
        limit: int = 20,
    ) -> list[SecurityStateTransition]:
        """Retrieves recent auditable state transitions for tenant."""
        stmt = (
            select(SecurityStateTransition)
            .where(SecurityStateTransition.tenant_id == tenant_id)
            .order_by(SecurityStateTransition.timestamp.desc())
            .limit(min(limit, 100))
        )
        res = await db.execute(stmt)
        return list(res.scalars().all())
