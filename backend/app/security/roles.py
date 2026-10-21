from collections.abc import Sequence
from enum import Enum

from fastapi import HTTPException, status


class Role(str, Enum):
    TENANT_ADMIN = "TENANT_ADMIN"
    SOC_L1 = "SOC_L1"
    SOC_L2 = "SOC_L2"
    SECURITY_ENGINEER = "SECURITY_ENGINEER"
    GRC_ANALYST = "GRC_ANALYST"
    SECURITY_MANAGER = "SECURITY_MANAGER"
    CISO = "CISO"

    @classmethod
    def all_roles(cls) -> list[str]:
        return [r.value for r in cls]


def check_role_permission(user_role: str, allowed_roles: Sequence[Role | str]) -> None:
    """Verifies that the user's role is in the allowed roles list, raising 403 Forbidden if not."""
    allowed_values = [r.value if isinstance(r, Role) else str(r) for r in allowed_roles]
    if user_role not in allowed_values:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation forbidden: insufficient role permissions.",
        )
