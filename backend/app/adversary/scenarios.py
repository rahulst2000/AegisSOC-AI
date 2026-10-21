from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from app.models.event import SecurityEvent


@dataclass
class AdversaryScenarioDefinition:
    scenario_id: str
    name: str
    description: str
    technique_id: str
    technique_name: str
    expected_rule_id: str
    expected_playbook_id: str
    default_target_asset: str
    default_target_ip: str
    tags: list[str] = field(default_factory=list)

    def generate_events(
        self,
        tenant_id: Any,
        target_asset: str,
        target_ip: str,
        assessment_id: Any,
    ) -> list[SecurityEvent]:
        """
        Generates controlled, safe telemetry simulating the specified MITRE ATT&CK technique.
        Never executes real destructive payloads, exploits, or persistent backdoors.
        """
        raise NotImplementedError


@dataclass
class SSHBruteForceScenario(AdversaryScenarioDefinition):
    def generate_events(
        self,
        tenant_id: Any,
        target_asset: str,
        target_ip: str,
        assessment_id: Any,
    ) -> list[SecurityEvent]:
        """SCENARIO-001: 10 Failed SSH Logins from single IP (T1110.001)"""
        base_time = datetime.now(UTC) - timedelta(minutes=2)
        events = []
        for i in range(10):
            evt = SecurityEvent(
                tenant_id=tenant_id,
                source="ssh",
                event_type="AUTH_FAILURE",
                severity="LOW",
                source_ip=target_ip,
                username="admin",
                hostname=target_asset,
                timestamp=base_time + timedelta(seconds=i * 5),
                raw_event={
                    "msg": "Failed password for admin",
                    "ip": target_ip,
                    "simulation": True,
                    "assessment_id": str(assessment_id),
                },
                normalized_event={
                    "event": {"type": "auth_failure"},
                    "source": {"ip": target_ip},
                    "simulation": True,
                    "assessment_id": str(assessment_id),
                },
            )
            events.append(evt)
        return events


@dataclass
class PasswordSprayingScenario(AdversaryScenarioDefinition):
    def generate_events(
        self,
        tenant_id: Any,
        target_asset: str,
        target_ip: str,
        assessment_id: Any,
    ) -> list[SecurityEvent]:
        """SCENARIO-002: Password spraying across 6 accounts from single IP (T1110.003)"""
        base_time = datetime.now(UTC) - timedelta(minutes=3)
        events = []
        target_users = ["alice", "bob", "charlie", "david", "emma", "frank"]
        for i, user in enumerate(target_users):
            evt = SecurityEvent(
                tenant_id=tenant_id,
                source="auth_service",
                event_type="AUTH_FAILURE",
                severity="LOW",
                source_ip=target_ip,
                username=user,
                hostname=target_asset,
                timestamp=base_time + timedelta(seconds=i * 10),
                raw_event={
                    "msg": f"Failed password for user {user}",
                    "ip": target_ip,
                    "simulation": True,
                    "assessment_id": str(assessment_id),
                },
                normalized_event={
                    "event": {"type": "auth_failure"},
                    "source": {"ip": target_ip},
                    "user": {"name": user},
                    "simulation": True,
                    "assessment_id": str(assessment_id),
                },
            )
            events.append(evt)
        return events


@dataclass
class FailureThenSuccessScenario(AdversaryScenarioDefinition):
    def generate_events(
        self,
        tenant_id: Any,
        target_asset: str,
        target_ip: str,
        assessment_id: Any,
    ) -> list[SecurityEvent]:
        """SCENARIO-003: 3 Authentication Failures followed by Success (T1078)"""
        base_time = datetime.now(UTC) - timedelta(minutes=4)
        events = []
        # 3 Failures
        for i in range(3):
            evt = SecurityEvent(
                tenant_id=tenant_id,
                source="auth_service",
                event_type="AUTH_FAILURE",
                severity="LOW",
                source_ip=target_ip,
                username="victim_user",
                hostname=target_asset,
                timestamp=base_time + timedelta(seconds=i * 8),
                raw_event={
                    "msg": "Invalid credentials",
                    "ip": target_ip,
                    "simulation": True,
                    "assessment_id": str(assessment_id),
                },
                normalized_event={
                    "event": {"type": "auth_failure"},
                    "source": {"ip": target_ip},
                    "simulation": True,
                    "assessment_id": str(assessment_id),
                },
            )
            events.append(evt)

        # 1 Success
        succ = SecurityEvent(
            tenant_id=tenant_id,
            source="auth_service",
            event_type="AUTH_SUCCESS",
            severity="INFO",
            source_ip=target_ip,
            username="victim_user",
            hostname=target_asset,
            timestamp=base_time + timedelta(seconds=35),
            raw_event={
                "msg": "Authentication success",
                "ip": target_ip,
                "simulation": True,
                "assessment_id": str(assessment_id),
            },
            normalized_event={
                "event": {"type": "auth_success"},
                "source": {"ip": target_ip},
                "simulation": True,
                "assessment_id": str(assessment_id),
            },
        )
        events.append(succ)
        return events


@dataclass
class PrivilegedLoginScenario(AdversaryScenarioDefinition):
    def generate_events(
        self,
        tenant_id: Any,
        target_asset: str,
        target_ip: str,
        assessment_id: Any,
    ) -> list[SecurityEvent]:
        """SCENARIO-004: Privileged Account Login (T1078.003)"""
        base_time = datetime.now(UTC) - timedelta(minutes=1)
        events = []
        evt = SecurityEvent(
            tenant_id=tenant_id,
            source="auth_service",
            event_type="AUTH_SUCCESS",
            severity="HIGH",
            source_ip=target_ip,
            username="root",
            hostname=target_asset,
            timestamp=base_time,
            raw_event={
                "msg": "Privileged login for root",
                "ip": target_ip,
                "simulation": True,
                "assessment_id": str(assessment_id),
            },
            normalized_event={
                "event": {"type": "auth_success", "privileged": True},
                "source": {"ip": target_ip},
                "user": {"name": "root"},
                "simulation": True,
                "assessment_id": str(assessment_id),
            },
        )
        events.append(evt)
        return events


SCENARIO_REGISTRY: dict[str, AdversaryScenarioDefinition] = {
    "SCENARIO-001": SSHBruteForceScenario(
        scenario_id="SCENARIO-001",
        name="SSH Authentication Brute Force Simulation",
        description="Generates controlled high-frequency authentication failures against authorized lab target.",
        technique_id="T1110.001",
        technique_name="Brute Force: Password Guessing",
        expected_rule_id="AEGIS-SIG-SSH-BRUTEFORCE",
        expected_playbook_id="PLAYBOOK-002",
        default_target_asset="lab-server-01",
        default_target_ip="198.51.100.25",
        tags=["credential_access", "brute_force", "ssh"],
    ),
    "SCENARIO-002": PasswordSprayingScenario(
        scenario_id="SCENARIO-002",
        name="Password Spraying Simulation",
        description="Generates controlled failed authentication attempts across multiple test identities.",
        technique_id="T1110.003",
        technique_name="Brute Force: Password Spraying",
        expected_rule_id="AEGIS-SIG-PASSWORD-SPRAYING",
        expected_playbook_id="PLAYBOOK-002",
        default_target_asset="lab-ad-01",
        default_target_ip="203.0.113.50",
        tags=["credential_access", "password_spray"],
    ),
    "SCENARIO-003": FailureThenSuccessScenario(
        scenario_id="SCENARIO-003",
        name="Failure → Success Account Takeover Simulation",
        description="Simulates credential guessing sequence followed by successful session acquisition.",
        technique_id="T1078",
        technique_name="Valid Accounts",
        expected_rule_id="AEGIS-SIG-FAILURE-THEN-SUCCESS",
        expected_playbook_id="PLAYBOOK-001",
        default_target_asset="lab-app-01",
        default_target_ip="198.51.100.77",
        tags=["defense_evasion", "persistence", "valid_accounts"],
    ),
    "SCENARIO-004": PrivilegedLoginScenario(
        scenario_id="SCENARIO-004",
        name="Privileged Login Simulation",
        description="Generates authorized privileged account login telemetry on sensitive asset.",
        technique_id="T1078.003",
        technique_name="Valid Accounts: Local Accounts (Privileged)",
        expected_rule_id="AEGIS-SIG-PRIVILEGED-LOGIN",
        expected_playbook_id="PLAYBOOK-005",
        default_target_asset="lab-bastion-01",
        default_target_ip="198.51.100.90",
        tags=["defense_evasion", "privileged_access"],
    ),
}


def get_scenario(scenario_id: str) -> AdversaryScenarioDefinition:
    """Retrieves scenario definition by ID or raises KeyError."""
    if scenario_id not in SCENARIO_REGISTRY:
        raise KeyError(f"Unknown scenario ID: {scenario_id}. Allowed: {list(SCENARIO_REGISTRY.keys())}")
    return SCENARIO_REGISTRY[scenario_id]
