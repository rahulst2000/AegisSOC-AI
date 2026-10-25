"""Detection Gap Engine for identifying gaps across the attack lifecycle."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adversary.models import AssessmentResult
from app.security_improvement.models import SecurityFinding
from app.security_improvement.schemas import DetectionGapReport


class GapEngine:
    """Evaluates assessment results and generates concrete security findings for identified gaps."""

    @staticmethod
    def analyze_result(result: AssessmentResult) -> list[DetectionGapReport]:
        """Examine an AssessmentResult and determine gaps across each stage.

        Rules:
        1. Attack simulated (PASS) but not detected (FAIL/NOT_TESTED) -> DETECTION_GAP
        2. Attack detected (PASS) but not correlated (FAIL) -> CORRELATION_GAP
        3. Attack correlated (PASS) but investigation failed (FAIL) -> INVESTIGATION_GAP
        4. Investigation succeeded (PASS) but response recommendation failed (FAIL) -> RESPONSE_GAP
        5. Response executed (PASS) but verification failed (FAIL) -> VERIFICATION_GAP
        """
        gaps: list[DetectionGapReport] = []

        # If simulation did not run or failed, we cannot accurately assess detection gaps
        if result.simulation_status != "PASS":
            return gaps

        assessment_id_str = str(result.assessment_id)
        target = result.target or "unknown-target"
        technique = result.technique_id or "UNKNOWN"
        scenario = result.scenario_id or "UNKNOWN"

        # 1. Detection Gap
        if result.detection_status in ("FAIL", "NOT_TESTED"):
            gaps.append(
                DetectionGapReport(
                    gap_type="DETECTION_GAP",
                    technique_id=technique,
                    target=target,
                    severity="HIGH",
                    summary=f"Attack simulation {scenario} ({technique}) executed on {target} but generated no detection alert.",
                    recommendation=f"Author or tune detection rules for MITRE technique {technique} to capture telemetry from {target}.",
                    assessment_id=assessment_id_str,
                    scenario_id=scenario,
                )
            )
            # If detection failed, downstream gaps are moot until detection is fixed
            return gaps

        # 2. Correlation Gap
        if result.correlation_status in ("FAIL", "NOT_TESTED"):
            gaps.append(
                DetectionGapReport(
                    gap_type="CORRELATION_GAP",
                    technique_id=technique,
                    target=target,
                    severity="MEDIUM",
                    summary=f"Detection occurred for {technique} on {target}, but correlation engine failed to link alert to an incident.",
                    recommendation=f"Adjust correlation window or entity aggregation logic for asset {target} and technique {technique}.",
                    assessment_id=assessment_id_str,
                    scenario_id=scenario,
                )
            )

        # 3. Investigation Gap
        if result.investigation_status in ("FAIL", "NOT_TESTED"):
            gaps.append(
                DetectionGapReport(
                    gap_type="INVESTIGATION_GAP",
                    technique_id=technique,
                    target=target,
                    severity="MEDIUM",
                    summary=f"Correlated incident for {technique} on {target} failed automated investigation or evidence collection.",
                    recommendation=f"Verify telemetry sources and investigation playbooks for {technique}.",
                    assessment_id=assessment_id_str,
                    scenario_id=scenario,
                )
            )

        # 4. Response Gap
        if result.response_status in ("FAIL", "NOT_TESTED"):
            gaps.append(
                DetectionGapReport(
                    gap_type="RESPONSE_GAP",
                    technique_id=technique,
                    target=target,
                    severity="HIGH",
                    summary=f"Investigation completed for {technique} on {target}, but no appropriate containment response was recommended.",
                    recommendation=f"Define or approve response playbooks (e.g. host isolation or credential revocation) for {technique}.",
                    assessment_id=assessment_id_str,
                    scenario_id=scenario,
                )
            )

        # 5. Verification Gap
        if result.response_status == "PASS" and result.verification_status in ("FAIL", "NOT_TESTED"):
            gaps.append(
                DetectionGapReport(
                    gap_type="VERIFICATION_GAP",
                    technique_id=technique,
                    target=target,
                    severity="HIGH",
                    summary=f"Response executed for {technique} on {target}, but post-action containment verification failed.",
                    recommendation="Review verification checks and response adapter telemetry to confirm containment enforcement.",
                    assessment_id=assessment_id_str,
                    scenario_id=scenario,
                )
            )

        return gaps

    @classmethod
    async def create_findings_from_result(
        cls,
        db: AsyncSession,
        tenant_id: uuid.UUID,
        result: AssessmentResult,
    ) -> list[SecurityFinding]:
        """Generates and persists SecurityFinding models for each detected gap in an assessment result."""
        gaps = cls.analyze_result(result)
        findings: list[SecurityFinding] = []

        for gap in gaps:
            # Check if an identical open finding already exists for this tenant, asset, and technique
            query = select(SecurityFinding).where(
                SecurityFinding.tenant_id == tenant_id,
                SecurityFinding.asset == gap.target,
                SecurityFinding.technique == gap.technique_id,
                SecurityFinding.title.like(f"%{gap.gap_type}%"),
                SecurityFinding.status.in_(["OPEN", "UNDER_REMEDIATION", "REOPENED"]),
            )
            existing = (await db.execute(query)).scalars().first()
            if existing:
                continue

            finding = SecurityFinding(
                tenant_id=tenant_id,
                assessment_id=result.assessment_id,
                severity=gap.severity,
                title=f"{gap.gap_type}: {gap.technique_id} on {gap.target}",
                description=gap.summary,
                asset=gap.target,
                technique=gap.technique_id,
                evidence_ids=result.evidence_ids or [],
                root_cause=f"Stage failure during adversary validation: {gap.gap_type}",
                business_impact=f"Attacker utilizing technique {gap.technique_id} against {gap.target} may evade SOC operational controls.",
                recommendation=gap.recommendation,
                priority="P1" if gap.severity in ("CRITICAL", "HIGH") else "P2",
                owner="Security Engineering",
                status="OPEN",
            )
            db.add(finding)
            findings.append(finding)

        if findings:
            await db.commit()
            for f in findings:
                await db.refresh(f)

        return findings


async def evaluate_gaps_for_assessment(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    result: AssessmentResult,
) -> list[SecurityFinding]:
    """Helper to evaluate gaps and create findings for an assessment result."""
    return await GapEngine.create_findings_from_result(db=db, tenant_id=tenant_id, result=result)
