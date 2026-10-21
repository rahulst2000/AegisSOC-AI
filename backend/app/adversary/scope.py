from datetime import UTC, datetime
from typing import Any

from app.policy.defaults import PROHIBITED_CONTAINMENT_IPS


def ensure_utc_datetime(val: Any) -> datetime:
    """Parses or normalizes a datetime to UTC."""
    if isinstance(val, datetime):
        if val.tzinfo is None:
            return val.replace(tzinfo=UTC)
        return val.astimezone(UTC)
    if isinstance(val, str):
        dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            return dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC)
    raise ValueError(f"Invalid datetime format: {val}")


def _validate_scope_dict(
    scope: dict[str, Any],
    target_asset: str | None = None,
    target_ip: str | None = None,
    technique_id: str | None = None,
) -> tuple[bool, str]:
    """Internal validator for scope dictionary."""
    if not scope:
        return False, "Scope Violation: Missing authorized_scope."

    # 1. Environment Check
    env = str(scope.get("environment", "")).upper()
    if env == "PRODUCTION":
        return (
            False,
            "Platform Safety Violation: Target environment is 'PRODUCTION'. "
            "Adversary validation is strictly forbidden against production.",
        )
    if env != "LAB":
        return (
            False,
            f"Platform Safety Violation: Simulations are strictly restricted to LAB environments. "
            f"Target environment '{env}' is rejected.",
        )

    # 2. Target Asset / Hostname Production Indicator Check
    all_specified_targets = (
        ([target_asset] if target_asset else []) + list(scope.get("assets", [])) + list(scope.get("hostnames", []))
    )
    for t_tgt in all_specified_targets:
        if t_tgt and "prod" in str(t_tgt).lower():
            return (
                False,
                f"Platform Safety Violation: Target asset '{t_tgt}' contains production indicator and cannot be targeted.",
            )

    # 3. Prohibited Techniques Check
    prohibited = [t.lower() for t in scope.get("prohibited_techniques", [])]
    if technique_id:
        tech_lower = technique_id.lower()
        for p in prohibited:
            if p in tech_lower or tech_lower in p:
                return (
                    False,
                    f"Scope Violation: Technique '{technique_id}' is explicitly PROHIBITED by scope policy.",
                )
    for allowed_t in scope.get("allowed_techniques", []):
        alt_lower = str(allowed_t).lower()
        for p in prohibited:
            if p in alt_lower or alt_lower in p:
                return (
                    False,
                    f"Scope Violation: Technique '{allowed_t}' is explicitly PROHIBITED by scope policy.",
                )

    # 4. Expiration Check
    expires_at_raw = scope.get("expires_at")
    if not expires_at_raw:
        return False, "Scope Violation: Scope expiration timestamp (expires_at) is required."

    try:
        expires_at = ensure_utc_datetime(expires_at_raw)
    except Exception as e:
        return False, f"Scope Violation: Malformed expiration timestamp: {e}"

    if expires_at <= datetime.now(UTC):
        return (
            False,
            f"Scope Violation: Scope authorization expired at {expires_at.isoformat()}.",
        )

    # 5. Human Approval Sign-off Check
    if not scope.get("authorized_by"):
        return False, "Scope Violation: Missing human authorization signature (authorized_by required)."

    # 6. Allowed Techniques Check
    allowed = scope.get("allowed_techniques", [])
    if technique_id and allowed and technique_id not in allowed:
        return (
            False,
            f"Scope Violation: Technique '{technique_id}' is not included in the authorized technique allowlist: {allowed}.",
        )

    # 7. Target Asset / Hostname Allowlist Check
    allowed_assets = set(scope.get("assets", []))
    allowed_hostnames = set(scope.get("hostnames", []))
    allowed_ips = set(scope.get("ips", []))
    all_allowed_targets = allowed_assets | allowed_hostnames | allowed_ips

    if not all_allowed_targets and not target_asset:
        return False, "Scope Violation: No target assets, hostnames, or IPs specified in scope."

    if target_asset and all_allowed_targets:
        target_matched = target_asset in all_allowed_targets or (target_ip and target_ip in all_allowed_targets)
        if not target_matched:
            return (
                False,
                f"Scope Violation: Target '{target_asset}' (IP: {target_ip}) is outside authorized scope targets: {list(all_allowed_targets)}.",
            )

    # 8. Safety checks on target IP
    if target_ip:
        if target_ip in PROHIBITED_CONTAINMENT_IPS or target_ip.startswith("127.") or target_ip == "::1":
            return (
                False,
                f"Platform Safety Violation: Target IP '{target_ip}' is a protected loopback/internal interface.",
            )

    return True, ""


def validate_assessment_scope(
    scope: dict[str, Any] | Any,
    target_asset: str | None = None,
    target_ip: str | None = None,
    technique_id: str | None = None,
) -> tuple[bool, str]:
    """
    Authoritative Scope Validator for AegisRed Adversary Simulations.
    Supports either dictionary scope or AdversaryAssessment model.
    """
    if hasattr(scope, "authorized_scope"):
        assessment = scope
        scope_dict = dict(assessment.authorized_scope or {})
        if assessment.environment and assessment.environment.upper() != "LAB":
            scope_dict["environment"] = assessment.environment

        target_asset = target_asset or (scope_dict.get("assets", [None])[0]) or (scope_dict.get("hostnames", [None])[0])
        target_ip = target_ip or (scope_dict.get("ips", [None])[0])
        technique_id = technique_id or (scope_dict.get("allowed_techniques", [None])[0])

        is_valid, err = _validate_scope_dict(scope_dict, target_asset, target_ip, technique_id)
        if not is_valid:
            raise ValueError(err)
        return is_valid, err

    return _validate_scope_dict(scope, target_asset, target_ip, technique_id)
