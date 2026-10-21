from typing import Any

# Global platform safety boundaries that cannot be overridden by tenant policy
PROHIBITED_CONTAINMENT_IPS = {
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "255.255.255.255",
}

DEFAULT_ACTION_POLICIES: dict[str, dict[str, Any]] = {
    "IP_CONTAINMENT": {
        "enabled": True,
        "min_role_for_approval": "SOC_L1_ANALYST",
        "require_human_approval": True,
        "conditions": {
            "prohibited_ips": list(PROHIBITED_CONTAINMENT_IPS),
        },
    },
    "ACCOUNT_LOCKOUT": {
        "enabled": True,
        "min_role_for_approval": "SOC_L1_ANALYST",
        "require_human_approval": True,
        "conditions": {
            "protected_accounts": ["breakglass_admin@aegis.internal"],
        },
    },
    "SESSION_REVOCATION": {
        "enabled": True,
        "min_role_for_approval": "SOC_L1_ANALYST",
        "require_human_approval": True,
        "conditions": {},
    },
    "HOST_ISOLATION": {
        "enabled": True,
        "min_role_for_approval": "SOC_L2_ANALYST",  # Higher risk of business downtime
        "require_human_approval": True,
        "conditions": {
            "protected_critical_hosts": ["dc01.corp", "core-router.internal"],
        },
    },
    "L2_ESCALATION": {
        "enabled": True,
        "min_role_for_approval": "SOC_L1_ANALYST",
        "require_human_approval": False,  # Non-destructive
        "conditions": {},
    },
    "COLLECT_EVIDENCE": {
        "enabled": True,
        "min_role_for_approval": "SOC_L1_ANALYST",
        "require_human_approval": False,  # Read-only
        "conditions": {},
    },
}
