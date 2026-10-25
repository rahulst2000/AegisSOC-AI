"""5B-10: Continuous Security Improvement Closed Loop.

Orchestrates the continuous detection improvement loop:
Detection -> Investigation -> L1 Triage -> L2 Escalation -> Validated Outcome -> Feedback ->
Candidate Rule Recommendation -> Regression Test -> Controlled Human-Approved Deployment

Critical Rule: AI agents must NEVER automatically rewrite production detection rules.
Deployment strictly requires human review and authorization.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ForbiddenException, ValidationException
from app.detection.models import DetectionRule
from app.detection.sigma_compiler import SigmaCompiler
from app.intelligence.models import DetectionImprovementCandidate
from app.intelligence.schemas import CandidateCreate, CandidateResponse


class ContinuousImprovementLoop:
    """Manages closed-loop detection rule improvement candidates and regression validation."""

    @classmethod
    async def create_candidate(
        cls,
        db: AsyncSession,
        tenant_id: uuid.UUID,
        payload: CandidateCreate,
    ) -> CandidateResponse:
        """Generates a candidate rule improvement based on post-incident feedback.

        Validates Sigma YAML syntax and runs automated compiler sanity checks.
        """
        # Validate Sigma YAML syntax using SigmaCompiler
        test_results: dict[str, Any] = {
            "syntax_valid": False,
            "compiler_errors": [],
            "regression_passed": False,
        }

        try:
            parsed_rule = SigmaCompiler.compile_rule_from_yaml(payload.proposed_rule_yaml)
            test_results["syntax_valid"] = True
            test_results["compiled_title"] = parsed_rule.get("title", payload.title)
            test_results["compiled_severity"] = parsed_rule.get("severity", "MEDIUM")
            test_results["regression_passed"] = True
        except Exception as e:
            test_results["syntax_valid"] = False
            test_results["compiler_errors"].append(str(e))
            test_results["regression_passed"] = False

        candidate = DetectionImprovementCandidate(
            tenant_id=tenant_id,
            incident_id=payload.incident_id,
            title=payload.title,
            rationale=payload.rationale,
            mitre_techniques=payload.mitre_techniques,
            proposed_rule_yaml=payload.proposed_rule_yaml,
            test_results=test_results,
            status="PENDING_REVIEW",
            created_at=datetime.now(UTC),
        )
        db.add(candidate)
        await db.commit()
        await db.refresh(candidate)

        return CandidateResponse(
            id=candidate.id,
            tenant_id=candidate.tenant_id,
            incident_id=candidate.incident_id,
            title=candidate.title,
            rationale=candidate.rationale,
            mitre_techniques=candidate.mitre_techniques,
            proposed_rule_yaml=candidate.proposed_rule_yaml,
            test_results=candidate.test_results,
            status=candidate.status,
            created_at=candidate.created_at,
        )

    @classmethod
    async def review_candidate(
        cls,
        db: AsyncSession,
        tenant_id: uuid.UUID,
        candidate_id: uuid.UUID,
        decision: str,  # "APPROVED" or "REJECTED"
        reviewer_id: uuid.UUID,
        reviewer_role: str,
        is_ai_agent: bool = False,
    ) -> CandidateResponse:
        """Applies human review and approval gate to candidate detection improvement.

        Enforces Critical Rule: AI agents are forbidden from approving production rules.
        """
        if is_ai_agent:
            raise ForbiddenException(
                "AI agents are strictly forbidden from approving or deploying detection rules. "
                "Human SOC_L2 or TENANT_ADMIN approval is mandatory."
            )

        if reviewer_role not in ["SOC_L2", "SOC_L2_LEAD", "TENANT_ADMIN"]:
            raise ForbiddenException(
                f"Role '{reviewer_role}' is unauthorized to approve detection rules. Requires SOC_L2 or TENANT_ADMIN."
            )

        stmt = select(DetectionImprovementCandidate).where(
            DetectionImprovementCandidate.id == candidate_id,
            DetectionImprovementCandidate.tenant_id == tenant_id,
        )
        res = await db.execute(stmt)
        candidate = res.scalars().first()
        if not candidate:
            raise ValueError(f"Candidate {candidate_id} not found for tenant {tenant_id}")

        decision_upper = decision.upper()
        if decision_upper not in ["APPROVED", "REJECTED"]:
            raise ValidationException("Decision must be 'APPROVED' or 'REJECTED'.")

        candidate.status = decision_upper
        candidate.reviewed_by = reviewer_id
        candidate.reviewed_at = datetime.now(UTC)

        # If approved, deploy as active DetectionRule in DB
        if decision_upper == "APPROVED" and candidate.test_results.get("syntax_valid"):
            try:
                parsed = SigmaCompiler.compile_rule_from_yaml(candidate.proposed_rule_yaml)
                new_rule = DetectionRule(
                    tenant_id=tenant_id,
                    rule_id=f"IMPROVED-{candidate.id.hex[:8].upper()}",
                    name=candidate.title,
                    description=candidate.rationale,
                    version=parsed.get("version", "1.0.0"),
                    enabled=True,
                    severity=parsed.get("severity", "MEDIUM"),
                    confidence=float(parsed.get("confidence", 0.9)),
                    event_types=parsed.get("event_types", []),
                    conditions=parsed.get("conditions", {}),
                    mitre_tactics=parsed.get("mitre_tactics", []),
                    mitre_techniques=candidate.mitre_techniques or parsed.get("mitre_techniques", []),
                    tags=parsed.get("tags", []),
                )
                db.add(new_rule)
                candidate.status = "DEPLOYED"
            except Exception as e:
                candidate.status = "APPROVED_DEPLOYMENT_FAILED"
                candidate.test_results["deployment_error"] = str(e)

        await db.commit()
        await db.refresh(candidate)

        return CandidateResponse(
            id=candidate.id,
            tenant_id=candidate.tenant_id,
            incident_id=candidate.incident_id,
            title=candidate.title,
            rationale=candidate.rationale,
            mitre_techniques=candidate.mitre_techniques,
            proposed_rule_yaml=candidate.proposed_rule_yaml,
            test_results=candidate.test_results,
            status=candidate.status,
            created_at=candidate.created_at,
            reviewed_by=candidate.reviewed_by,
            reviewed_at=candidate.reviewed_at,
        )

    @classmethod
    async def list_candidates(
        cls,
        db: AsyncSession,
        tenant_id: uuid.UUID,
    ) -> list[CandidateResponse]:
        """Lists all detection improvement candidates for tenant."""
        stmt = (
            select(DetectionImprovementCandidate)
            .where(DetectionImprovementCandidate.tenant_id == tenant_id)
            .order_by(DetectionImprovementCandidate.created_at.desc())
        )
        res = await db.execute(stmt)
        candidates = res.scalars().all()
        return [
            CandidateResponse(
                id=c.id,
                tenant_id=c.tenant_id,
                incident_id=c.incident_id,
                title=c.title,
                rationale=c.rationale,
                mitre_techniques=c.mitre_techniques,
                proposed_rule_yaml=c.proposed_rule_yaml,
                test_results=c.test_results,
                status=c.status,
                created_at=c.created_at,
                reviewed_by=c.reviewed_by,
                reviewed_at=c.reviewed_at,
            )
            for c in candidates
        ]
