import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class SecurityEventCreate(BaseModel):
    source: str = Field(..., max_length=100, description="Log source: EDR, FIREWALL, SYSLOG, etc.")
    event_type: str = Field(..., max_length=100, description="Event classification: AUTH_FAILURE, MALWARE, etc.")
    severity: str = Field(default="MEDIUM", max_length=50, description="INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL")
    source_ip: str | None = Field(None, max_length=45, description="Source IP address")
    username: str | None = Field(None, max_length=255, description="Subject username")
    hostname: str | None = Field(None, max_length=255, description="Target host")
    raw_event: dict[str, Any] = Field(..., description="Original raw telemetry event payload")
    normalized_event: dict[str, Any] | None = Field(None, description="Normalized ECS/OCSF schema representation")
    timestamp: datetime | None = Field(None, description="Event generation timestamp")


class SecurityEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    timestamp: datetime
    source: str
    event_type: str
    severity: str
    source_ip: str | None
    username: str | None
    hostname: str | None
    raw_event: dict[str, Any]
    normalized_event: dict[str, Any]
    created_at: datetime
