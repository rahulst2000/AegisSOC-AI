import uuid
from collections.abc import Callable, Sequence
from typing import Any

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.user import User
from app.security.roles import Role, check_role_permission
from app.security.tenant import TenantContext
from app.security.tokens import decode_token

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/v1/auth/login",
    auto_error=False,
)


async def get_current_token_payload(token: str | None = Depends(oauth2_scheme)) -> dict[str, Any]:
    """
    Validates the bearer token and extracts token claims.
    Fails securely with HTTP 401 when the token is missing or invalid.
    """
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token is missing.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_token(token)
        return payload
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired authentication token: {str(exc)}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


async def get_current_user(
    payload: dict[str, Any] = Depends(get_current_token_payload),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Resolves the authenticated User record from the database.
    Guarantees user exists, belongs to the declared tenant, and is ACTIVE.
    """
    try:
        user_id = uuid.UUID(payload["sub"])
        tenant_id = uuid.UUID(payload["tenant_id"])
    except (KeyError, ValueError) as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed token claims.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from err

    stmt = select(User).where(User.id == user_id, User.tenant_id == tenant_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User identity could not be verified.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user.status != "ACTIVE":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"User account is {user.status.lower()}.",
        )

    return user


async def get_tenant_context(
    user: User = Depends(get_current_user),
) -> TenantContext:
    """
    Provides an immutable TenantContext verified from authenticated server session.
    Guarantees client cannot override or forge tenant_id.
    """
    return TenantContext(
        tenant_id=user.tenant_id,
        user_id=user.id,
        email=user.email,
        role=user.role,
    )


def require_roles(allowed_roles: Sequence[Role | str]) -> Callable:
    """
    Dependency factory enforcing Role-Based Access Control (RBAC).
    Raises HTTP 403 if the authenticated user lacks one of the required roles.
    """

    async def role_checker(user: User = Depends(get_current_user)) -> User:
        check_role_permission(user.role, allowed_roles)
        return user

    return role_checker
