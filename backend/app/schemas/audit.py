import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AuditLogCreate(BaseModel):
    user_id: uuid.UUID | None = Field(None, description="Acting user ID if authenticated")
    action: str = Field(..., max_length=100, description="Security action name")
    resource_type: str = Field(..., max_length=100, description="Target entity type")
    resource_id: str | None = Field(None, max_length=255, description="Target entity identifier")
    result: str = Field(..., max_length=50, description="SUCCESS, FAILURE, DENIED")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Contextual request metadata")


class AuditLogRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    user_id: uuid.UUID | None
    action: str
    resource_type: str
    resource_id: str | None
    result: str
    timestamp: datetime
    metadata: dict[str, Any] = Field(..., alias="metadata_")
