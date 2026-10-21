import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.policy.defaults import DEFAULT_ACTION_POLICIES, PROHIBITED_CONTAINMENT_IPS
from app.policy.models import SecurityPolicy
from app.policy.schemas import PolicyDecision


class PolicyEvaluator:
    """
    Authoritative policy evaluation engine.
    Applies platform safety rules, tenant policies, and approval role requirements.
    """

    def __init__(self, db: AsyncSession, tenant_id: uuid.UUID):
        self.db = db
        self.tenant_id = tenant_id

    async def evaluate_action(
        self,
        action_type: str,
        target_entity: str,
        target_type: str,
    ) -> PolicyDecision:
        """
        Evaluates whether a requested action is permitted, which role must approve it,
        and whether human approval is mandatory.
        """
        action_upper = action_type.strip().upper()

        # 1. Platform Safety Layer (Hardcoded inviolable constraints)
        if action_upper == "IP_CONTAINMENT":
            if target_entity in PROHIBITED_CONTAINMENT_IPS or target_entity.startswith("127."):
                return PolicyDecision(
                    allowed=False,
                    reason=f"Target IP '{target_entity}' is protected by platform safety rules (loopback/broadcast).",
                    required_approval_role="DISABLED",
                    require_human_approval=True,
                    policy_name="PLATFORM_SAFETY_INVIOLABLE",
                )

        # 2. Query Tenant-Specific Policy from DB
        stmt = select(SecurityPolicy).where(
            SecurityPolicy.tenant_id == self.tenant_id,
            SecurityPolicy.action_type == action_upper,
        )
        res = await self.db.execute(stmt)
        policy = res.scalars().first()

        # 3. Fallback to System Defaults if no tenant override
        if not policy:
            default_config = DEFAULT_ACTION_POLICIES.get(action_upper)
            if not default_config:
                return PolicyDecision(
                    allowed=False,
                    reason=f"Action type '{action_type}' is not recognized by system policy.",
                    required_approval_role="DISABLED",
                    require_human_approval=True,
                    policy_name="UNKNOWN_ACTION_DEFAULT_DENY",
                )

            if not default_config["enabled"]:
                return PolicyDecision(
                    allowed=False,
                    reason=f"Action '{action_type}' is disabled by default platform policy.",
                    required_approval_role="DISABLED",
                    require_human_approval=True,
                    policy_name="DEFAULT_DISABLED",
                )

            # Check protected entities
            conditions = default_config.get("conditions", {})
            if target_entity in conditions.get("protected_accounts", []):
                return PolicyDecision(
                    allowed=False,
                    reason=f"Account '{target_entity}' is a protected break-glass identity.",
                    required_approval_role="DISABLED",
                    require_human_approval=True,
                    policy_name="DEFAULT_PROTECTED_ACCOUNT",
                )
            if target_entity in conditions.get("protected_critical_hosts", []):
                return PolicyDecision(
                    allowed=False,
                    reason=f"Host '{target_entity}' is a protected critical infrastructure asset.",
                    required_approval_role="DISABLED",
                    require_human_approval=True,
                    policy_name="DEFAULT_PROTECTED_HOST",
                )

            return PolicyDecision(
                allowed=True,
                reason="Permitted under default platform policy with human approval gate.",
                required_approval_role=default_config["min_role_for_approval"],
                require_human_approval=default_config["require_human_approval"],
                policy_name="DEFAULT_PLATFORM_POLICY",
            )

        # 4. Evaluate Custom Tenant Policy
        if not policy.enabled:
            return PolicyDecision(
                allowed=False,
                reason=f"Action '{action_type}' has been disabled by tenant policy '{policy.name}'.",
                required_approval_role="DISABLED",
                require_human_approval=True,
                policy_name=policy.name,
            )

        conditions = policy.conditions or {}
        if target_entity in conditions.get("excluded_ips", []):
            return PolicyDecision(
                allowed=False,
                reason=f"IP '{target_entity}' is excluded from automated containment by tenant policy.",
                required_approval_role="DISABLED",
                require_human_approval=True,
                policy_name=policy.name,
            )

        return PolicyDecision(
            allowed=True,
            reason=f"Permitted under tenant policy '{policy.name}'.",
            required_approval_role=policy.min_role_for_approval,
            require_human_approval=policy.require_human_approval,
            policy_name=policy.name,
        )
