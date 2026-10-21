import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class L2EscalationCreate(BaseModel):
    reason: str = Field(..., min_length=5, max_length=1000)
    urgency: str = Field(default="HIGH", description="NORMAL, HIGH, CRITICAL")


class L2EscalationRead(BaseModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    investigation_id: uuid.UUID | None
    tenant_id: uuid.UUID
    escalated_by: uuid.UUID | None
    escalated_at: datetime
    reason: str
    urgency: str
    status: str
    l2_package: dict[str, Any]

    class Config:
        from_attributes = True
