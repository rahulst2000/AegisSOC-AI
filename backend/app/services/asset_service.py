import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset import Asset
from app.schemas.asset import AssetCreate
from app.services.audit_service import log_audit_event


async def create_asset(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    asset_in: AssetCreate,
    user_id: uuid.UUID | None = None,
) -> Asset:
    """
    Creates an asset strictly bounded to the authenticated tenant.
    Client-side tenant_id is never accepted.
    """
    asset = Asset(
        tenant_id=tenant_id,
        hostname=asset_in.hostname,
        ip_address=asset_in.ip_address,
        asset_type=asset_in.asset_type,
        criticality=asset_in.criticality,
        environment=asset_in.environment,
        status=asset_in.status,
    )
    db.add(asset)
    await db.flush()

    await log_audit_event(
        db=db,
        tenant_id=tenant_id,
        user_id=user_id,
        action="CREATE_ASSET",
        resource_type="ASSET",
        resource_id=str(asset.id),
        result="SUCCESS",
        metadata={"hostname": asset.hostname, "ip": asset.ip_address},
    )

    await db.commit()
    await db.refresh(asset)
    return asset


async def get_assets(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    skip: int = 0,
    limit: int = 100,
) -> list[Asset]:
    """
    Retrieves assets strictly isolated to the authenticated tenant.
    Never allows cross-tenant query execution.
    """
    stmt = select(Asset).where(Asset.tenant_id == tenant_id).order_by(Asset.created_at.desc()).offset(skip).limit(limit)
    result = await db.execute(stmt)
    return list(result.scalars().all())
