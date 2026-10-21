"""Security Posture Scoring engine calculating evidence-grounded posture metrics."""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adversary.mitre_coverage import get_mitre_coverage_matrix
from app.security_improvement.models import SecurityFinding
from app.security_improvement.schemas import SecurityPostureReport, SecurityPostureScore


class PostureScoringEngine:
    """Calculates posture metrics backed strictly by validated adversary tests and findings."""

    # Map categories to relevant techniques
    CATEGORY_TECHNIQUE_MAP: dict[str, list[str]] = {
        "Identity Security": ["T1110.001", "T1110.003", "T1078", "T1078.003"],
        "Detection Coverage": ["T1110.001", "T1110.003", "T1078", "T1078.003"],
        "Incident Response": ["T1110.001", "T1110.003", "T1078", "T1078.003"],
        "Endpoint Security": ["T1078.003"],
        "Network Security": ["T1110.001"],
        "Security Monitoring": ["T1110.001", "T1110.003"],
        "Vulnerability Management": [],  # Evaluated by finding remediation metrics
    }

    @classmethod
    async def generate_posture_report(
        cls,
        db: AsyncSession,
        tenant_id: uuid.UUID,
    ) -> SecurityPostureReport:
        """Generates comprehensive evidence-backed security posture report.

        Distinguishes TEST COVERAGE (metrics over executed adversary validations)
        from OVERALL POSTURE (factoring in open findings and overall resilience).
        """
        matrix = await get_mitre_coverage_matrix(db, tenant_id)
        technique_results = {item["technique_id"]: item for item in matrix}

        # Query finding stats
        open_findings_count = (
            await db.scalar(
                select(func.count(SecurityFinding.id)).where(
                    SecurityFinding.tenant_id == tenant_id,
                    SecurityFinding.status.in_(["OPEN", "UNDER_REMEDIATION", "REOPENED"]),
                )
            )
            or 0
        )

        verified_findings_count = (
            await db.scalar(
                select(func.count(SecurityFinding.id)).where(
                    SecurityFinding.tenant_id == tenant_id,
                    SecurityFinding.status.in_(["VERIFIED", "CLOSED"]),
                )
            )
            or 0
        )

        total_findings = open_findings_count + verified_findings_count
        remediation_rate = round((verified_findings_count / total_findings * 100.0), 2) if total_findings > 0 else 100.0

        category_scores: list[SecurityPostureScore] = []
        category_percentages: list[float] = []

        for category, techniques in cls.CATEGORY_TECHNIQUE_MAP.items():
            if not techniques:
                # Handle Vulnerability Management via remediation success
                category_scores.append(
                    SecurityPostureScore(
                        category=category,
                        tested_techniques=total_findings,
                        successful_detections=verified_findings_count,
                        coverage_percentage=remediation_rate,
                        status="OPTIMAL"
                        if remediation_rate >= 80
                        else ("NEEDS_ATTENTION" if total_findings > 0 else "NO_FINDINGS"),
                    )
                )
                category_percentages.append(remediation_rate)
                continue

            tested_count = 0
            success_count = 0

            for t_id in techniques:
                item = technique_results.get(t_id)
                if not item or item["simulation"] == "NOT_TESTED":
                    continue
                tested_count += 1
                if category == "Incident Response":
                    # For incident response, overall or response must be PASS
                    if item["response"] == "PASS" and item["verification"] == "PASS":
                        success_count += 1
                else:
                    if item["detection"] == "PASS":
                        success_count += 1

            if tested_count > 0:
                pct = round((success_count / tested_count) * 100.0, 2)
                status = "PASS" if pct == 100.0 else ("PARTIAL" if pct > 0 else "FAIL")
            else:
                pct = 0.0
                status = "NOT_TESTED"

            category_scores.append(
                SecurityPostureScore(
                    category=category,
                    tested_techniques=tested_count,
                    successful_detections=success_count,
                    coverage_percentage=pct,
                    status=status,
                )
            )
            if tested_count > 0:
                category_percentages.append(pct)

        # Distinguish Test Coverage vs Overall Posture
        total_tested = sum(1 for m in matrix if m["simulation"] != "NOT_TESTED")
        total_detected = sum(1 for m in matrix if m["detection"] == "PASS")
        test_coverage_pct = round((total_detected / total_tested * 100.0), 2) if total_tested > 0 else 0.0

        if category_percentages:
            base_score = sum(category_percentages) / len(category_percentages)
            # Penalize for unmitigated open findings (5 pts per finding up to 30)
            finding_penalty = min(open_findings_count * 5.0, 30.0)
            overall_posture = max(0.0, round(base_score - finding_penalty, 2))
        else:
            overall_posture = 0.0

        return SecurityPostureReport(
            test_coverage_percentage=test_coverage_pct,
            overall_posture_score=overall_posture,
            categories=category_scores,
            total_findings_open=open_findings_count,
            total_findings_remediated=verified_findings_count,
            remediation_success_rate=remediation_rate,
        )
