import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class SecurityPolicyBase(BaseModel):
    name: str = Field(..., max_length=255)
    action_type: str = Field(..., max_length=100)
    enabled: bool = True
    min_role_for_approval: str = Field(default="SOC_L1_ANALYST")
    require_human_approval: bool = True
    conditions: dict[str, Any] = Field(default_factory=dict)


class SecurityPolicyCreate(SecurityPolicyBase):
    pass


class SecurityPolicyRead(SecurityPolicyBase):
    id: uuid.UUID
    tenant_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class PolicyDecision(BaseModel):
    allowed: bool
    reason: str
    required_approval_role: str
    require_human_approval: bool
    policy_name: str = "DEFAULT_PLATFORM_SAFETY"
