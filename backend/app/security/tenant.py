import uuid
from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException, status


@dataclass(frozen=True)
class TenantContext:
    """
    Immutable representation of an authenticated tenant context.
    Strictly derived from verified server-side authentication tokens.
    Never populated from unauthenticated client request bodies or query params.
    """

    tenant_id: uuid.UUID
    user_id: uuid.UUID
    email: str
    role: str

    def assert_tenant_match(self, resource_tenant_id: uuid.UUID) -> None:
        """
        Guarantees that a resource belongs to the current tenant context.
        Raises HTTP 404 (or 403) to strictly deny cross-tenant information disclosure.
        Returning 404 prevents oracle attacks confirming existence of cross-tenant resources.
        """
        if resource_tenant_id != self.tenant_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Resource not found.",
            )


def enforce_tenant_query(query: Any, model: Any, tenant_id: uuid.UUID) -> Any:
    """
    Applies strict tenant_id filtering to any SQLAlchemy select or update query.
    Prevents accidental leakage of records across tenant boundaries.
    """
    if not hasattr(model, "tenant_id"):
        raise AttributeError(f"Model {model.__name__} does not have a tenant_id attribute for isolation.")
    return query.where(model.tenant_id == tenant_id)
