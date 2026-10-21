import uuid

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.tenant import Tenant
from app.schemas.tenant import TenantCreate


async def get_tenant_by_id(db: AsyncSession, tenant_id: uuid.UUID) -> Tenant | None:
    """Retrieves a tenant by primary key."""
    result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
    return result.scalar_one_or_none()


async def get_tenant_by_name(db: AsyncSession, name: str) -> Tenant | None:
    """Retrieves a tenant by unique name."""
    result = await db.execute(select(Tenant).where(Tenant.name == name))
    return result.scalar_one_or_none()


async def create_tenant(db: AsyncSession, tenant_in: TenantCreate) -> Tenant:
    """Creates a new organizational tenant."""
    existing = await get_tenant_by_name(db, tenant_in.name)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Tenant '{tenant_in.name}' already exists.",
        )

    tenant = Tenant(
        name=tenant_in.name,
        status="ACTIVE",
    )
    db.add(tenant)
    await db.commit()
    await db.refresh(tenant)
    return tenant
