"""Detection Coverage Engine calculating MITRE ATT&CK and telemetry coverage."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.adversary.mitre_coverage import get_mitre_coverage_matrix
from app.security_improvement.schemas import MitreCoverageItem


class CoverageEngine:
    """Computes evidence-backed detection and adversary validation coverage."""

    @staticmethod
    async def get_coverage_matrix(
        db: AsyncSession,
        tenant_id: uuid.UUID,
    ) -> list[MitreCoverageItem]:
        """Returns the full ATT&CK coverage matrix backed by real assessment results."""
        matrix_data = await get_mitre_coverage_matrix(db, tenant_id)
        items: list[MitreCoverageItem] = []
        for d in matrix_data:
            items.append(
                MitreCoverageItem(
                    technique_id=d["technique_id"],
                    technique_name=d["technique_name"],
                    tactics=d["tactics"],
                    simulation=d["simulation"],
                    detection=d["detection"],
                    correlation=d["correlation"],
                    investigation=d["investigation"],
                    response=d["response"],
                    verification=d["verification"],
                    overall=d["overall"],
                )
            )
        return items

    @staticmethod
    async def get_test_coverage_summary(
        db: AsyncSession,
        tenant_id: uuid.UUID,
    ) -> dict[str, Any]:
        """Calculates specific test coverage metrics strictly from executed assessments.

        Never fabricates metrics. If 4 techniques are in registry and 4 tested, tested=4.
        """
        matrix = await get_mitre_coverage_matrix(db, tenant_id)
        total_techniques = len(matrix)
        tested_techniques = sum(1 for m in matrix if m["simulation"] != "NOT_TESTED")
        detected_techniques = sum(1 for m in matrix if m["detection"] == "PASS")
        fully_contained_techniques = sum(1 for m in matrix if m["overall"] == "PASS")

        coverage_pct = round((detected_techniques / tested_techniques * 100.0), 2) if tested_techniques > 0 else 0.0

        return {
            "total_supported_techniques": total_techniques,
            "tested_techniques": tested_techniques,
            "detected_techniques": detected_techniques,
            "fully_contained_techniques": fully_contained_techniques,
            "detection_test_coverage_percentage": coverage_pct,
        }
