from typing import Any

import yaml

MAX_SIGMA_RULE_SIZE_BYTES = 1024 * 1024  # 1 MB safety ceiling


class SigmaParseError(ValueError):
    """Raised when a Sigma rule is structurally invalid or violates security constraints."""

    pass


def parse_sigma_yaml(content: str) -> dict[str, Any]:
    """
    Safely parses a Sigma rule definition string using PyYAML SafeLoader.
    Enforces maximum payload size limits and verifies essential schema fields.
    """
    if not content or not content.strip():
        raise SigmaParseError("Sigma rule content cannot be empty.")

    if len(content.encode("utf-8")) > MAX_SIGMA_RULE_SIZE_BYTES:
        raise SigmaParseError(f"Rule exceeds maximum allowable size of {MAX_SIGMA_RULE_SIZE_BYTES} bytes.")

    try:
        parsed = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise SigmaParseError(f"YAML syntax violation: {str(exc)}") from exc

    if not isinstance(parsed, dict):
        raise SigmaParseError("Root element of Sigma rule must be a mapping dictionary.")

    # Validate mandatory Sigma fields
    mandatory_fields = ["title", "logsource", "detection"]
    for field in mandatory_fields:
        if field not in parsed:
            raise SigmaParseError(f"Missing mandatory Sigma specification field: '{field}'")

    if not isinstance(parsed["detection"], dict):
        raise SigmaParseError("The 'detection' section must be a dictionary.")

    if "condition" not in parsed["detection"]:
        raise SigmaParseError("The 'detection' section must declare a 'condition'.")

    return parsed


def extract_mitre_from_tags(tags: list[str] | None) -> tuple[list[str], list[str]]:
    """
    Extracts MITRE ATT&CK tactics and techniques from standard Sigma tags.
    e.g. ['attack.credential_access', 'attack.t1110.001'] -> (['Credential Access'], ['T1110.001'])
    """
    tactics: set[str] = set()
    techniques: set[str] = set()

    if not tags:
        return ([], [])

    tactic_lookup = {
        "initial_access": "Initial Access",
        "execution": "Execution",
        "persistence": "Persistence",
        "privilege_escalation": "Privilege Escalation",
        "defense_evasion": "Defense Evasion",
        "credential_access": "Credential Access",
        "discovery": "Discovery",
        "lateral_movement": "Lateral Movement",
        "collection": "Collection",
        "command_and_control": "Command and Control",
        "exfiltration": "Exfiltration",
        "impact": "Impact",
    }

    for tag in tags:
        tag_lower = tag.lower().strip()
        if tag_lower.startswith("attack.t"):
            # Technique tag: attack.t1110 or attack.t1110.001
            tech_id = tag[7:].upper()
            techniques.add(tech_id)
        elif tag_lower.startswith("attack."):
            tactic_key = tag_lower[7:]
            if tactic_key in tactic_lookup:
                tactics.add(tactic_lookup[tactic_key])

    return (sorted(tactics), sorted(techniques))
