import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class IncidentBase(BaseModel):
    title: str = Field(..., min_length=2, max_length=255, description="Incident title")
    description: str = Field(..., min_length=5, description="Detailed incident description")
    severity: str = Field(default="MEDIUM", max_length=50, description="LOW, MEDIUM, HIGH, CRITICAL")
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Calculated risk score")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence metric (0.0 - 1.0)")
    status: str = Field(
        default="OPEN",
        max_length=50,
        description="OPEN, INVESTIGATING, CONTAINED, RESOLVED, CLOSED",
    )


class IncidentCreate(IncidentBase):
    pass


class IncidentUpdate(BaseModel):
    title: str | None = Field(None, min_length=2, max_length=255)
    description: str | None = Field(None, min_length=5)
    severity: str | None = Field(None, max_length=50)
    risk_score: float | None = Field(None, ge=0.0, le=100.0)
    confidence: float | None = Field(None, ge=0.0, le=1.0)
    status: str | None = Field(None, max_length=50)


class IncidentRead(IncidentBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    created_at: datetime
    updated_at: datetime
