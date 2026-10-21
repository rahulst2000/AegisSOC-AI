import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class PlaybookRead(BaseModel):
    id: uuid.UUID
    playbook_id: str
    tenant_id: uuid.UUID | None
    name: str
    description: str
    action_type: str
    required_role: str
    risk_level: str
    enabled: bool
    parameters_schema: dict[str, Any]
    created_at: datetime

    class Config:
        from_attributes = True


class ActionRequestCreate(BaseModel):
    incident_id: uuid.UUID
    investigation_id: uuid.UUID | None = None
    action_type: str = Field(..., description="IP_CONTAINMENT, ACCOUNT_LOCKOUT, etc.")
    target_entity: str = Field(..., description="Target IP, username, hostname")
    target_type: str = Field(..., description="IP, USER, HOST, INCIDENT")
    playbook_id: str = Field(..., description="PLAYBOOK-001, PLAYBOOK-002, etc.")


class ActionApprovalRequest(BaseModel):
    reason: str | None = Field(None, max_length=500)


class ActionRejectionRequest(BaseModel):
    reason: str = Field(..., min_length=3, max_length=500)


class ActionRequestRead(BaseModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    investigation_id: uuid.UUID | None
    tenant_id: uuid.UUID
    action_type: str
    target_entity: str
    target_type: str
    playbook_id: str
    requested_by: uuid.UUID | None
    requested_at: datetime
    policy_evaluation: dict[str, Any]
    required_approval_role: str
    approval_status: str
    approved_by: uuid.UUID | None
    approved_at: datetime | None
    rejection_reason: str | None
    execution_status: str
    verification_status: str
    evidence_before: dict[str, Any]
    evidence_after: dict[str, Any]
    result: dict[str, Any]
    error: str | None
    timestamp: datetime

    class Config:
        from_attributes = True


class VerificationResultRead(BaseModel):
    action_id: uuid.UUID
    verification_status: str  # VERIFIED, VERIFICATION_FAILED
    details: str
    before_state: dict[str, Any]
    after_state: dict[str, Any]
    verified_at: datetime
