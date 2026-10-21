import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class EvidenceBase(BaseModel):
    evidence_type: str = Field(..., max_length=100, description="LOG_SNIPPET, FILE_HASH, NETWORK_CAPTURE, etc.")
    description: str = Field(..., description="Contextual description of evidence")
    source: str = Field(..., max_length=255, description="Telemetry origin or sensor name")
    integrity_hash: str = Field(..., min_length=64, max_length=64, description="Cryptographic SHA-256 integrity hash")


class EvidenceCreate(EvidenceBase):
    incident_id: uuid.UUID | None = Field(None, description="Associated incident ID")
    event_id: uuid.UUID | None = Field(None, description="Associated security event ID")


class EvidenceRead(EvidenceBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    incident_id: uuid.UUID | None
    event_id: uuid.UUID | None
    created_at: datetime
