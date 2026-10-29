from collections.abc import Sequence
from enum import Enum

from fastapi import HTTPException, status


class Role(str, Enum):
    TENANT_ADMIN = "TENANT_ADMIN"
    SOC_L1 = "SOC_L1"
    SOC_L1_ANALYST = "SOC_L1_ANALYST"
    SOC_L2 = "SOC_L2"
    SOC_L2_ANALYST = "SOC_L2_ANALYST"
    SECURITY_ENGINEER = "SECURITY_ENGINEER"
    THREAT_HUNTER = "THREAT_HUNTER"
    AUDITOR = "AUDITOR"
    VIEWER = "VIEWER"
    GRC_ANALYST = "GRC_ANALYST"
    SECURITY_MANAGER = "SECURITY_MANAGER"
    CISO = "CISO"

    @classmethod
    def all_roles(cls) -> list[str]:
        return [r.value for r in cls]


def normalize_role(role: str) -> str:
    """Normalizes role aliases to canonical representations."""
    aliases = {
        "SOC_L1_ANALYST": "SOC_L1",
        "SOC_L2_ANALYST": "SOC_L2",
    }
    cleaned = role.strip().upper()
    return aliases.get(cleaned, cleaned)


def check_role_permission(user_role: str, allowed_roles: Sequence[Role | str]) -> None:
    """Verifies that the user's role is in the allowed roles list, raising 403 Forbidden if not."""
    norm_user_role = normalize_role(user_role)
    allowed_values = [normalize_role(r.value if isinstance(r, Role) else str(r)) for r in allowed_roles]
    # If TENANT_ADMIN is in user_role, they have super-privileges within their tenant
    if norm_user_role == Role.TENANT_ADMIN.value or norm_user_role in allowed_values:
        return

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Operation forbidden: insufficient role permissions.",
    )
