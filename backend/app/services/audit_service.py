import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import logger
from app.models.audit import AuditLog


async def log_audit_event(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    action: str,
    resource_type: str,
    result: str,
    user_id: uuid.UUID | None = None,
    resource_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> AuditLog:
    """
    Creates an immutable audit log record for security-sensitive operations.
    Guarantees tenant attribution and action traceability.
    """
    try:
        audit_entry = AuditLog(
            tenant_id=tenant_id,
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            result=result,
            metadata_=metadata or {},
        )
        db.add(audit_entry)
        await db.flush()
        return audit_entry
    except Exception as exc:
        logger.error(
            f"Failed to persist audit log: {str(exc)}",
            extra={"tenant_id": str(tenant_id), "action": action},
        )
        # Audit logging failure should not silently pass in production
        raise
