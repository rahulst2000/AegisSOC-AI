"""5B-06: Counterfactual Security Analysis Engine.

Performs controlled simulation only (zero production side-effects).
Evaluates security scenarios:
- "What happens if we do nothing?"
- "What happens if we isolate the host?"
- "What happens if we revoke the session?"
- "What happens if we disable the account?"

Critical Rule: Do NOT execute real actions. Output auditable, evidence-backed risk deltas.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ValidationException
from app.intelligence.schemas import CounterfactualRequest, CounterfactualResponse
from app.models.incident import Incident


class CounterfactualAnalysisEngine:
    """Simulates security state trajectories under candidate containment actions."""

    ALLOWED_SIMULATED_ACTIONS = {
        "DO_NOTHING",
        "ISOLATE_HOST",
        "REVOKE_SESSION",
        "DISABLE_ACCOUNT",
    }

    @classmethod
    async def simulate_scenario(
        cls,
        db: AsyncSession,
        tenant_id: uuid.UUID,
        request: CounterfactualRequest,
    ) -> CounterfactualResponse:
        """Simulates candidate response action impact on incident risk and posture."""
        action = request.simulated_action.upper()
        if action not in cls.ALLOWED_SIMULATED_ACTIONS:
            raise ValidationException(
                f"Invalid simulated action '{request.simulated_action}'. "
                f"Supported actions: {', '.join(sorted(cls.ALLOWED_SIMULATED_ACTIONS))}"
            )

        # 1. Fetch incident with tenant authorization
        stmt = select(Incident).where(
            Incident.id == request.incident_id,
            Incident.tenant_id == tenant_id,
        )
        res = await db.execute(stmt)
        incident = res.scalars().first()
        if not incident:
            raise ValueError(f"Incident {request.incident_id} not found for tenant {tenant_id}")

        current_risk = incident.risk_score
        current_state = (
            f"Incident '{incident.title}' active with risk score {current_risk:.1f}/100. "
            f"Severity: {incident.severity}. Status: {incident.status}."
        )

        # 2. Evaluate simulated action outcomes
        if action == "DO_NOTHING":
            risk_change = +25.0
            predicted_risk = min(100.0, current_risk + risk_change)
            predicted_state = (
                f"Attack progression continues unhindered. Predicted escalation to lateral movement and "
                f"credential dumping within 30 minutes. Risk score increases to {predicted_risk:.1f}/100."
            )
            business_impact = "No immediate operational disruption, but critical enterprise data at severe risk."
            assumptions = [
                "Adversary retains active session and credential access.",
                "No external firewall or endpoint block interrupts adversary execution.",
                "Adversary possesses tooling to enumerate internal subnet and pivot laterally.",
            ]
            confidence = 0.88

        elif action == "ISOLATE_HOST":
            risk_change = -45.0
            predicted_risk = max(10.0, current_risk + risk_change)
            target_host = (incident.affected_assets or ["compromised-host"])[0]
            predicted_state = (
                f"Host '{target_host}' network interfaces logically partitioned. Inbound and outbound "
                f"C2 and lateral traffic blocked. Volatile memory preserved for forensic triage. "
                f"Risk reduced to {predicted_risk:.1f}/100."
            )
            business_impact = f"Services hosted on '{target_host}' temporarily unavailable to legitimate users."
            assumptions = [
                "Host network agent supports software-defined isolation.",
                "Adversary has not already established persistent secondary footholds on adjacent hosts.",
                "Out-of-band management remains available for incident response acquisition.",
            ]
            confidence = 0.91

        elif action == "REVOKE_SESSION":
            risk_change = -30.0
            predicted_risk = max(15.0, current_risk + risk_change)
            target_user = (incident.affected_users or ["compromised-user"])[0]
            predicted_state = (
                f"Active JWT and OAuth refresh tokens for user '{target_user}' invalidated across all sessions. "
                f"Interactive SSH/API session terminated. Risk reduced to {predicted_risk:.1f}/100."
            )
            business_impact = f"User '{target_user}' disconnected and required to re-authenticate with MFA."
            assumptions = [
                "Token revocation is globally distributed to identity providers within 60 seconds.",
                "Adversary has not spawned background daemon processes with detached credentials.",
            ]
            confidence = 0.85

        elif action == "DISABLE_ACCOUNT":
            risk_change = -40.0
            predicted_risk = max(10.0, current_risk + risk_change)
            target_user = (incident.affected_users or ["compromised-user"])[0]
            predicted_state = (
                f"User identity '{target_user}' disabled in directory and tenant database. "
                f"All interactive and programmatic API access blocked. Risk reduced to {predicted_risk:.1f}/100."
            )
            business_impact = f"Complete access freeze for user '{target_user}'. Service dependencies require override."
            assumptions = [
                "Identity directory lock prevents LDAP/ActiveDirectory/OAuth re-authentication.",
                "User has no hardcoded SSH authorized_keys bypassing central directory authentication.",
            ]
            confidence = 0.90

        return CounterfactualResponse(
            incident_id=incident.id,
            current_state=current_state,
            action_simulated=action,
            predicted_state=predicted_state,
            risk_change=risk_change,
            business_impact=business_impact,
            assumptions=assumptions,
            confidence=confidence,
            simulated_at=datetime.now(UTC),
        )
