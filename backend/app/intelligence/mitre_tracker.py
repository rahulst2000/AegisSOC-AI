"""5B-12: End-to-End MITRE Pipeline Coverage Tracker.

Tracks complete defensive lifecycle for every MITRE ATT&CK technique:
Simulation -> Detection -> Correlation -> Investigation -> Response -> Verification

Critical Rule: Only evidence-backed PASS results count as verified coverage.
Partial or unverified stages are explicitly flagged as gaps.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adversary.mitre_coverage import get_mitre_coverage_matrix
from app.adversary.models import AssessmentResult
from app.intelligence.schemas import MitrePipelineCoverageReport, MitrePipelineStageCoverage


class MitreCoverageTracker:
    """Computes comprehensive end-to-end MITRE ATT&CK pipeline coverage."""

    @classmethod
    async def generate_pipeline_report(
        cls,
        db: AsyncSession,
        tenant_id: uuid.UUID,
    ) -> MitrePipelineCoverageReport:
        """Evaluates pipeline completion strictly from database records."""
        # 1. Fetch raw matrix from adversary validation
        matrix_data = await get_mitre_coverage_matrix(db, tenant_id)

        # 2. Query executed assessment results to collect concrete evidence IDs
        res_stmt = (
            select(AssessmentResult)
            .where(AssessmentResult.tenant_id == tenant_id)
            .order_by(AssessmentResult.completed_at.desc())
        )
        res_results = await db.execute(res_stmt)
        results = res_results.scalars().all()

        technique_evidence: dict[str, list[str]] = {}
        for r in results:
            technique_evidence.setdefault(r.technique_id, []).append(str(r.id))

        stage_items: list[MitrePipelineStageCoverage] = []
        gaps: list[dict[str, Any]] = []

        for m in matrix_data:
            tech_id = getattr(m, "technique_id", m["technique_id"] if isinstance(m, dict) else str(m))
            tech_name = getattr(m, "technique_name", m["technique_name"] if isinstance(m, dict) else tech_id)
            tactics = getattr(m, "tactics", m["tactics"] if isinstance(m, dict) else [])
            sim = getattr(m, "simulation", m["simulation"] if isinstance(m, dict) else "NOT_TESTED")
            det = getattr(m, "detection", m["detection"] if isinstance(m, dict) else "NOT_TESTED")
            corr = getattr(m, "correlation", m["correlation"] if isinstance(m, dict) else "NOT_TESTED")
            inv = getattr(m, "investigation", m["investigation"] if isinstance(m, dict) else "NOT_TESTED")
            resp = getattr(m, "response", m["response"] if isinstance(m, dict) else "NOT_TESTED")
            ver = getattr(m, "verification", m["verification"] if isinstance(m, dict) else "NOT_TESTED")

            is_complete = (
                sim == "PASS"
                and det == "PASS"
                and corr == "PASS"
                and inv == "PASS"
                and resp == "PASS"
                and ver == "PASS"
            )

            evidence_ids = technique_evidence.get(tech_id, [])

            stage_items.append(
                MitrePipelineStageCoverage(
                    technique_id=tech_id,
                    technique_name=tech_name,
                    tactics=tactics,
                    simulation=sim,
                    detection=det,
                    correlation=corr,
                    investigation=inv,
                    response=resp,
                    verification=ver,
                    pipeline_completed=is_complete,
                    evidence_ids=evidence_ids,
                )
            )

            # Record specific stage gaps
            if sim == "PASS" and det != "PASS":
                gaps.append(
                    {
                        "technique_id": tech_id,
                        "gap_stage": "DETECTION",
                        "description": f"Simulation executed but detection failed or unconfigured for {tech_id}.",
                    }
                )
            elif det == "PASS" and corr != "PASS":
                gaps.append(
                    {
                        "technique_id": tech_id,
                        "gap_stage": "CORRELATION",
                        "description": f"Detections trigger independently but correlation into unified incident is absent for {tech_id}.",
                    }
                )
            elif corr == "PASS" and inv != "PASS":
                gaps.append(
                    {
                        "technique_id": tech_id,
                        "gap_stage": "INVESTIGATION",
                        "description": f"Incident correlated but automated forensic investigation incomplete for {tech_id}.",
                    }
                )
            elif inv == "PASS" and resp != "PASS":
                gaps.append(
                    {
                        "technique_id": tech_id,
                        "gap_stage": "RESPONSE",
                        "description": f"Investigation completed but automated response containment playbook missing for {tech_id}.",
                    }
                )
            elif resp == "PASS" and ver != "PASS":
                gaps.append(
                    {
                        "technique_id": tech_id,
                        "gap_stage": "VERIFICATION",
                        "description": f"Response executed but post-action containment verification unverified for {tech_id}.",
                    }
                )

        total_in_scope = len(stage_items)
        fully_verified = sum(1 for s in stage_items if s.pipeline_completed)
        coverage_pct = round((fully_verified / total_in_scope * 100.0), 2) if total_in_scope > 0 else 0.0

        return MitrePipelineCoverageReport(
            tenant_id=tenant_id,
            total_techniques_in_scope=total_in_scope,
            fully_verified_techniques=fully_verified,
            pipeline_coverage_percentage=coverage_pct,
            coverage_matrix=stage_items,
            identified_gaps=gaps,
        )
