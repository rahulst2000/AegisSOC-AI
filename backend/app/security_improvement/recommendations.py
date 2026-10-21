"""Recommendations engine for detection tuning and false positive improvement."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.incident import Incident


class RecommendationEngine:
    """Generates detection tuning and false-positive reduction recommendations.

    SAFETY INVARIANT:
    The engine NEVER automatically modifies detection rules or policies.
    All outputs are non-destructive recommendations requiring explicit human review.
    """

    @staticmethod
    async def analyze_false_positive_trends(
        db: AsyncSession,
        tenant_id: uuid.UUID,
    ) -> list[dict[str, Any]]:
        """Analyzes closed incidents marked FALSE_POSITIVE or BENIGN to propose rule tuning."""
        query = select(Incident).where(
            Incident.tenant_id == tenant_id,
            Incident.status == "CLOSED",
            Incident.severity.in_(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
        )
        incidents = (await db.execute(query)).scalars().all()

        recommendations: list[dict[str, Any]] = []

        # Analyze repetitive false positives or benign findings
        fp_patterns: dict[str, int] = {}
        for inc in incidents:
            inv = inc.investigation_result or {}
            decision = inc.analyst_decision or inv.get("conclusion")
            summary = (inc.summary or "").lower()
            if decision == "FALSE_POSITIVE" or "benign" in summary or "scanner" in summary:
                rule_name = inv.get("matched_rule") or inc.title or "Generic Alert"
                fp_patterns[rule_name] = fp_patterns.get(rule_name, 0) + 1

        for rule, count in fp_patterns.items():
            if count >= 1:
                recommendations.append(
                    {
                        "type": "FALSE_POSITIVE_TUNING",
                        "rule_target": rule,
                        "observation_count": count,
                        "current_behavior": f"{count} incident(s) triggered by this pattern were determined to be benign or false-positives.",
                        "recommendation": (
                            f"Tune rule '{rule}' by adding an asset allowlist, verifying routine service accounts, "
                            "or increasing threshold limits to reduce operational noise."
                        ),
                        "suggested_action": "EXCLUDE_KNOWN_SCANNER_OR_HOST",
                        "requires_human_approval": True,
                        "auto_applied": False,
                    }
                )

        return recommendations

    @staticmethod
    def generate_gap_recommendations(technique_id: str, asset: str) -> dict[str, Any]:
        """Provides concrete detection engineering guidance for a verified adversary gap."""
        guidance = {
            "T1110.001": {
                "rule_name": "SIGMA-SSH-BRUTEFORCE",
                "recommendation": f"Deploy or adjust SSH authentication threshold rule for {asset}: trigger after 5 failures in 120s from single source IP.",
                "mitre_id": "T1110.001",
            },
            "T1110.003": {
                "rule_name": "SIGMA-PASSWORD-SPRAY",
                "recommendation": f"Deploy password spraying detection for {asset}: aggregate failed logins across >= 3 accounts from single IP.",
                "mitre_id": "T1110.003",
            },
            "T1078": {
                "rule_name": "SIGMA-AUTH-FAILURE-SUCCESS",
                "recommendation": f"Deploy sequence detection on {asset}: correlate >= 3 auth failures immediately followed by 1 successful login.",
                "mitre_id": "T1078",
            },
            "T1078.003": {
                "rule_name": "SIGMA-PRIVILEGED-LOGIN",
                "recommendation": f"Enable privileged logon monitoring on {asset}: alert on interactive root/administrator logons from unapproved subnets.",
                "mitre_id": "T1078.003",
            },
        }

        default_guidance = {
            "rule_name": f"RULE-{technique_id}",
            "recommendation": f"Develop custom Sigma detection rule for {technique_id} targeting host telemetry on {asset}.",
            "mitre_id": technique_id,
        }

        return guidance.get(technique_id, default_guidance)
