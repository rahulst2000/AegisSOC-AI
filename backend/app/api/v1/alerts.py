from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_tenant_context
from app.schemas.alert import AlertRead
from app.security.tenant import TenantContext
from app.services.incident_service import get_alerts

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("", response_model=list[AlertRead], status_code=status.HTTP_200_OK)
async def list_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieves detection alerts generated for the authenticated tenant.
    """
    return await get_alerts(
        db=db,
        tenant_id=ctx.tenant_id,
        skip=skip,
        limit=limit,
    )
