from dataclasses import dataclass
from typing import ClassVar


@dataclass(frozen=True)
class MitreTechnique:
    technique_id: str
    name: str
    tactics: list[str]
    description: str


class MitreAttackCatalog:
    """
    Authoritative reference repository for MITRE ATT&CK Enterprise tactics and techniques.
    Ensures validation of technique IDs and provides normalized metadata across detections.
    """

    _CATALOG: ClassVar[dict[str, MitreTechnique]] = {
        "T1110": MitreTechnique(
            technique_id="T1110",
            name="Brute Force",
            tactics=["Credential Access"],
            description=(
                "Adversaries may use brute force techniques to attempt access to accounts "
                "when passwords or credentials are unknown."
            ),
        ),
        "T1110.001": MitreTechnique(
            technique_id="T1110.001",
            name="Password Guessing",
            tactics=["Credential Access"],
            description=(
                "Adversaries may systematically guess passwords to authenticate "
                "against single or multiple user accounts."
            ),
        ),
        "T1110.003": MitreTechnique(
            technique_id="T1110.003",
            name="Password Spraying",
            tactics=["Credential Access"],
            description=(
                "Adversaries may use a single or small list of commonly used passwords "
                "against many accounts to evade lockout policies."
            ),
        ),
        "T1078": MitreTechnique(
            technique_id="T1078",
            name="Valid Accounts",
            tactics=["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
            description=(
                "Adversaries may obtain and abuse credentials of existing accounts as a means "
                "of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion."
            ),
        ),
        "T1078.003": MitreTechnique(
            technique_id="T1078.003",
            name="Local Accounts",
            tactics=["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
            description=(
                "Adversaries may compromise credentials of a local administrator or built-in "
                "system account to establish access."
            ),
        ),
        "T1059": MitreTechnique(
            technique_id="T1059",
            name="Command and Scripting Interpreter",
            tactics=["Execution"],
            description=(
                "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries."
            ),
        ),
        "T1003": MitreTechnique(
            technique_id="T1003",
            name="OS Credential Dumping",
            tactics=["Credential Access"],
            description=(
                "Adversaries may attempt to dump credentials from the operating system, "
                "including LSASS memory, SAM database, or secrets."
            ),
        ),
        "T1046": MitreTechnique(
            technique_id="T1046",
            name="Network Service Discovery",
            tactics=["Discovery"],
            description=(
                "Adversaries may attempt to enumerate active hosts and listening services "
                "using port scanning or network probes."
            ),
        ),
    }

    @classmethod
    def get_technique(cls, technique_id: str) -> MitreTechnique | None:
        return cls._CATALOG.get(technique_id.strip().upper())

    @classmethod
    def validate_technique_id(cls, technique_id: str) -> bool:
        return technique_id.strip().upper() in cls._CATALOG

    @classmethod
    def resolve_tactics(cls, technique_ids: list[str]) -> list[str]:
        tactics_set: set[str] = set()
        for tid in technique_ids:
            tech = cls.get_technique(tid)
            if tech:
                tactics_set.update(tech.tactics)
        return sorted(tactics_set)

    @classmethod
    def all_techniques(cls) -> list[MitreTechnique]:
        return list(cls._CATALOG.values())
