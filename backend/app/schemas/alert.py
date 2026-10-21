import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class AlertCreate(BaseModel):
    event_id: uuid.UUID | None = Field(None, description="Underlying security event ID")
    detection_rule: str = Field(..., max_length=255, description="Triggered detection rule or SIGMA rule")
    severity: str = Field(default="MEDIUM", max_length=50)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    status: str = Field(default="OPEN", max_length=50)


class AlertRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    event_id: uuid.UUID | None
    detection_rule: str
    severity: str
    confidence: float
    status: str
    created_at: datetime
