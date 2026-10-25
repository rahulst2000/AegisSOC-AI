from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_tenant_context
from app.models.audit import AuditLog
from app.schemas.audit import AuditLogRead
from app.security.tenant import TenantContext

router = APIRouter(prefix="/audit", tags=["Audit Logging"])


@router.get("", response_model=list[AuditLogRead], status_code=status.HTTP_200_OK)
async def list_audit_logs(
    db: Annotated[AsyncSession, Depends(get_db)],
    tenant_ctx: Annotated[TenantContext, Depends(get_tenant_context)],
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    """
    Returns immutable audit logs scoped strictly to the authenticated tenant.
    """
    stmt = (
        select(AuditLog)
        .where(AuditLog.tenant_id == tenant_ctx.tenant_id)
        .order_by(desc(AuditLog.timestamp))
        .offset(offset)
        .limit(limit)
    )
    result = await db.execute(stmt)
    return result.scalars().all()
