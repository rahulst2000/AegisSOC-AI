from typing import Any

STANDARD_PLAYBOOKS: dict[str, dict[str, Any]] = {
    "PLAYBOOK-001": {
        "playbook_id": "PLAYBOOK-001",
        "name": "Account Lockout Recommendation",
        "description": "Temporarily locks an active directory or cloud account to prevent unauthorized access.",
        "action_type": "ACCOUNT_LOCKOUT",
        "required_role": "SOC_L1_ANALYST",
        "risk_level": "MEDIUM",
        "parameters_schema": {"username": {"type": "string", "required": True}},
    },
    "PLAYBOOK-002": {
        "playbook_id": "PLAYBOOK-002",
        "name": "IP Containment Recommendation",
        "description": "Applies perimeter firewall or security group block against malicious adversary IP.",
        "action_type": "IP_CONTAINMENT",
        "required_role": "SOC_L1_ANALYST",
        "risk_level": "MEDIUM",
        "parameters_schema": {"ip_address": {"type": "string", "required": True}},
    },
    "PLAYBOOK-003": {
        "playbook_id": "PLAYBOOK-003",
        "name": "Session Revocation Recommendation",
        "description": "Terminates active sessions and invalidates refresh tokens for potentially compromised user.",
        "action_type": "SESSION_REVOCATION",
        "required_role": "SOC_L1_ANALYST",
        "risk_level": "LOW",
        "parameters_schema": {"username": {"type": "string", "required": True}},
    },
    "PLAYBOOK-004": {
        "playbook_id": "PLAYBOOK-004",
        "name": "Host Isolation Recommendation",
        "description": "Isolates an endpoint from the enterprise network while preserving SOC management access.",
        "action_type": "HOST_ISOLATION",
        "required_role": "SOC_L2_ANALYST",
        "risk_level": "HIGH",
        "parameters_schema": {"hostname": {"type": "string", "required": True}},
    },
    "PLAYBOOK-005": {
        "playbook_id": "PLAYBOOK-005",
        "name": "Incident Escalation to Tier-2 SOC",
        "description": "Compiles comprehensive investigation package and routes incident to Senior L2 Analyst queue.",
        "action_type": "L2_ESCALATION",
        "required_role": "SOC_L1_ANALYST",
        "risk_level": "LOW",
        "parameters_schema": {"incident_id": {"type": "string", "required": True}},
    },
    "PLAYBOOK-006": {
        "playbook_id": "PLAYBOOK-006",
        "name": "Collect Additional Evidence",
        "description": "Dispatches automated forensic queries to gather extended user and host telemetry.",
        "action_type": "COLLECT_EVIDENCE",
        "required_role": "SOC_L1_ANALYST",
        "risk_level": "LOW",
        "parameters_schema": {"target": {"type": "string", "required": True}},
    },
}


def get_playbook_definition(playbook_id: str) -> dict[str, Any] | None:
    """Retrieves standard playbook definition by ID."""
    return STANDARD_PLAYBOOKS.get(playbook_id.strip().upper())
