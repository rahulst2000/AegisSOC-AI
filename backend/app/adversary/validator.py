from typing import Any

from app.adversary.scope import validate_assessment_scope


def check_adversary_authorization_role(user_role: str) -> None:
    """
    Enforces that only authorized Security personnel (SOC_L2, SOC_L2_LEAD, SECURITY_ENGINEER, SECURITY_MANAGER, CISO, TENANT_ADMIN)
    can authorize an adversary validation assessment.
    """
    allowed_roles = {
        "SOC_L2",
        "SOC_L2_LEAD",
        "SOC_ADMIN",
        "SECURITY_ENGINEER",
        "SECURITY_MANAGER",
        "TENANT_ADMIN",
        "SUPER_ADMIN",
        "CISO",
    }
    if user_role not in allowed_roles:
        raise PermissionError(
            f"Role Authorization Failure: Role '{user_role}' is not authorized to sign off on "
            f"adversary validation assessments. Minimum required: SOC_L2."
        )


def validate_ai_boundary_for_adversary(caller_type: str, action: str) -> None:
    """
    Guarantees AI models cannot authorize, execute, or expand scope for adversary simulations.
    """
    if caller_type.upper() in {"AI", "LLM", "AGENT", "AUTOMATION"}:
        raise PermissionError(
            f"AI Security Directive Violation: AI models are strictly prohibited from performing '{action}'. "
            f"Human approval is mandatory."
        )


def validate_scope_for_scenario(
    scope: dict[str, Any],
    target_asset: str,
    target_ip: str | None,
    technique_id: str,
) -> None:
    """
    Validates scope against scenario requirements and raises ValueError on violation.
    """
    is_valid, reason = validate_assessment_scope(
        scope=scope,
        target_asset=target_asset,
        target_ip=target_ip,
        technique_id=technique_id,
    )
    if not is_valid:
        raise ValueError(reason)
