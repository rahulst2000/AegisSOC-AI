"""Service layer for Security Improvement, Findings, Remediation, and Retesting."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.adversary.models import AssessmentResult
from app.core.exceptions import NotFoundException
from app.security_improvement.coverage import CoverageEngine
from app.security_improvement.gap_engine import GapEngine
from app.security_improvement.models import RemediationAction, SecurityFinding
from app.security_improvement.recommendations import RecommendationEngine
from app.security_improvement.remediation import RemediationEngine
from app.security_improvement.retest import RetestEngine
from app.security_improvement.schemas import (
    DetectionGapReport,
    MitreCoverageItem,
    RemediationActionCreate,
    SecurityFindingCreate,
    SecurityPostureReport,
)
from app.security_improvement.scoring import PostureScoringEngine
from app.services.audit_service import log_audit_event


class SecurityImprovementService:
    """Orchestrates security improvement operations."""

    @staticmethod
    async def list_findings(
        db: AsyncSession,
        tenant_id: uuid.UUID,
        status: str | None = None,
        severity: str | None = None,
    ) -> list[SecurityFinding]:
        """Lists security findings with optional filters, eagerly loading remediations."""
        query = (
            select(SecurityFinding)
            .where(SecurityFinding.tenant_id == tenant_id)
            .options(selectinload(SecurityFinding.remediations))
            .order_by(SecurityFinding.created_at.desc())
        )
        if status:
            query = query.where(SecurityFinding.status == status)
        if severity:
            query = query.where(SecurityFinding.severity == severity)

        return list((await db.execute(query)).scalars().all())

    @staticmethod
    async def get_finding(
        db: AsyncSession,
        tenant_id: uuid.UUID,
        finding_id: uuid.UUID,
    ) -> SecurityFinding:
        """Retrieves a single finding with remediations."""
        query = (
            select(SecurityFinding)
            .where(
                SecurityFinding.id == finding_id,
                SecurityFinding.tenant_id == tenant_id,
            )
            .options(selectinload(SecurityFinding.remediations))
        )
        finding = (await db.execute(query)).scalars().first()
        if not finding:
            raise NotFoundException(f"Security finding {finding_id} not found.")
        return finding

    @staticmethod
    async def create_finding(
        db: AsyncSession,
        tenant_id: uuid.UUID,
        payload: SecurityFindingCreate,
    ) -> SecurityFinding:
        """Directly create a security finding."""
        finding = SecurityFinding(
            tenant_id=tenant_id,
            assessment_id=payload.assessment_id,
            severity=payload.severity,
            title=payload.title,
            description=payload.description,
            asset=payload.asset,
            technique=payload.technique,
            evidence_ids=payload.evidence_ids,
            root_cause=payload.root_cause,
            business_impact=payload.business_impact,
            recommendation=payload.recommendation,
            priority=payload.priority,
            owner=payload.owner,
            status="OPEN",
        )
        db.add(finding)
        await db.commit()
        await db.refresh(finding)

        await log_audit_event(
            db=db,
            tenant_id=tenant_id,
            action="FINDING_CREATED",
            resource_type="finding",
            resource_id=str(finding.id),
            result="SUCCESS",
            user_id=None,
            metadata={"title": finding.title, "severity": finding.severity},
        )
        return finding

    @staticmethod
    async def get_gaps(
        db: AsyncSession,
        tenant_id: uuid.UUID,
    ) -> list[DetectionGapReport]:
        """Scans all recent assessment results for the tenant to identify all gaps."""
        query = (
            select(AssessmentResult)
            .where(AssessmentResult.tenant_id == tenant_id)
            .order_by(AssessmentResult.created_at.desc())
        )
        results = (await db.execute(query)).scalars().all()

        all_gaps: list[DetectionGapReport] = []
        for res in results:
            gaps = GapEngine.analyze_result(res)
            all_gaps.extend(gaps)
        return all_gaps

    @staticmethod
    async def get_coverage_matrix(
        db: AsyncSession,
        tenant_id: uuid.UUID,
    ) -> list[MitreCoverageItem]:
        """Calculates ATT&CK coverage matrix."""
        return await CoverageEngine.get_coverage_matrix(db, tenant_id)

    @staticmethod
    async def get_posture_report(
        db: AsyncSession,
        tenant_id: uuid.UUID,
    ) -> SecurityPostureReport:
        """Calculates evidence-backed posture report."""
        return await PostureScoringEngine.generate_posture_report(db, tenant_id)

    @staticmethod
    async def get_recommendations(
        db: AsyncSession,
        tenant_id: uuid.UUID,
    ) -> list[dict[str, Any]]:
        """Returns false-positive tuning and detection recommendations."""
        return await RecommendationEngine.analyze_false_positive_trends(db, tenant_id)

    @staticmethod
    async def create_remediation(
        db: AsyncSession,
        tenant_id: uuid.UUID,
        finding_id: uuid.UUID,
        payload: RemediationActionCreate,
    ) -> RemediationAction:
        """Creates a pending remediation."""
        return await RemediationEngine.create_remediation(db, tenant_id, finding_id, payload)

    @staticmethod
    async def approve_remediation(
        db: AsyncSession,
        tenant_id: uuid.UUID,
        remediation_id: uuid.UUID,
        approver_id: uuid.UUID,
        user_role: str,
        is_ai_agent: bool = False,
    ) -> RemediationAction:
        """Approves a remediation with human verification."""
        return await RemediationEngine.approve_remediation(
            db=db,
            tenant_id=tenant_id,
            remediation_id=remediation_id,
            approver_id=approver_id,
            user_role=user_role,
            is_ai_agent=is_ai_agent,
        )

    @staticmethod
    async def retest_finding(
        db: AsyncSession,
        tenant_id: uuid.UUID,
        finding_id: uuid.UUID,
        user_id: uuid.UUID,
        user_role: str,
        is_ai_agent: bool = False,
        simulate_regression_failure: bool = False,
    ) -> dict[str, Any]:
        """Executes an authorized retest for a finding."""
        return await RetestEngine.retest_finding(
            db=db,
            tenant_id=tenant_id,
            finding_id=finding_id,
            user_id=user_id,
            user_role=user_role,
            is_ai_agent=is_ai_agent,
            simulate_regression_failure=simulate_regression_failure,
        )
