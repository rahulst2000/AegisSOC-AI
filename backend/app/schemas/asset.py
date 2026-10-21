import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class AssetBase(BaseModel):
    hostname: str = Field(..., min_length=1, max_length=255, description="FQDN or Hostname")
    ip_address: str = Field(..., min_length=7, max_length=45, description="IPv4 or IPv6 address")
    asset_type: str = Field(default="SERVER", max_length=50, description="SERVER, WORKSTATION, CLOUD, etc.")
    criticality: str = Field(default="MEDIUM", max_length=50, description="LOW, MEDIUM, HIGH, CRITICAL")
    environment: str = Field(default="PRODUCTION", max_length=50, description="PRODUCTION, STAGING, LAB, etc.")
    status: str = Field(default="ACTIVE", max_length=50, description="ACTIVE, OFFLINE, DECOMMISSIONED")


class AssetCreate(AssetBase):
    """Client creation schema. Notice: tenant_id is NOT accepted here to prevent tenant spoofing."""

    pass


class AssetUpdate(BaseModel):
    hostname: str | None = Field(None, min_length=1, max_length=255)
    ip_address: str | None = Field(None, min_length=7, max_length=45)
    asset_type: str | None = Field(None, max_length=50)
    criticality: str | None = Field(None, max_length=50)
    environment: str | None = Field(None, max_length=50)
    status: str | None = Field(None, max_length=50)


class AssetRead(AssetBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    created_at: datetime
    updated_at: datetime
