import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.security.roles import Role


class UserBase(BaseModel):
    email: EmailStr = Field(..., description="Corporate email address")
    role: Role = Field(default=Role.SOC_L1, description="Assigned SOC role")


class UserCreate(UserBase):
    password: str = Field(..., min_length=8, max_length=128, description="Strong user password")


class UserRead(UserBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    status: str
    created_at: datetime
    updated_at: datetime
