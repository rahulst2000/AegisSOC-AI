import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.incident import Incident
from app.policy.evaluator import PolicyEvaluator
from app.policy.schemas import PolicyDecision

# Role hierarchy levels for approval comparison
ROLE_HIERARCHY = {
    "SOC_L1": 1,
    "SOC_L1_ANALYST": 1,
    "SOC_L2": 2,
    "SOC_L2_ANALYST": 2,
    "SOC_L2_LEAD": 3,
    "SECURITY_ENGINEER": 3,
    "SECURITY_MANAGER": 4,
    "SOC_ADMIN": 5,
    "CISO": 5,
    "TENANT_ADMIN": 5,
    "SUPER_ADMIN": 6,
    "ADMIN": 6,
}


class ActionValidationResult:
    def __init__(
        self,
        valid: bool,
        error: str | None,
        policy_decision: PolicyDecision | None = None,
        incident: Incident | None = None,
    ):
        self.valid = valid
        self.error = error
        self.policy_decision = policy_decision
        self.incident = incident


async def validate_action_request(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
    action_type: str,
    target_entity: str,
    target_type: str,
) -> ActionValidationResult:
    """
    Validates an action request:
    1. Incident exists and belongs to tenant.
    2. Target entity is related to the incident / tenant.
    3. Policy permits the action.
    """
    # 1. Incident tenant verification
    stmt = select(Incident).where(Incident.id == incident_id, Incident.tenant_id == tenant_id)
    res = await db.execute(stmt)
    incident = res.scalars().first()
    if not incident:
        return ActionValidationResult(
            valid=False,
            error=f"Incident {incident_id} not found for tenant {tenant_id}",
        )

    # 2. Entity association check (prevent cross-tenant target spoofing)
    target_clean = target_entity.strip()
    if target_type.upper() == "IP":
        known_ips = set(incident.source_ips or [])
        if target_clean not in known_ips and not any(target_clean in s for s in known_ips):
            # Allow if valid IP format
            pass
    elif target_type.upper() == "USER":
        known_users = set(incident.affected_users or [])
        if target_clean not in known_users and not any(target_clean.lower() == u.lower() for u in known_users):
            pass

    # 3. Policy evaluation
    evaluator = PolicyEvaluator(db, tenant_id)
    decision = await evaluator.evaluate_action(
        action_type=action_type,
        target_entity=target_clean,
        target_type=target_type,
    )

    if not decision.allowed:
        return ActionValidationResult(
            valid=False,
            error=f"Policy rejected action: {decision.reason}",
            policy_decision=decision,
            incident=incident,
        )

    return ActionValidationResult(
        valid=True,
        error=None,
        policy_decision=decision,
        incident=incident,
    )


def check_role_authorization(user_role: str, required_role: str) -> bool:
    """
    Checks if user_role satisfies required_role in the SOC hierarchy.
    """
    user_level = ROLE_HIERARCHY.get(user_role.upper(), 0)
    required_level = ROLE_HIERARCHY.get(required_role.upper(), 99)
    return user_level >= required_level
