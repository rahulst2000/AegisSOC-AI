import uuid

from pydantic import BaseModel, EmailStr, Field

from app.schemas.user import UserRead
from app.security.roles import Role


class UserRegister(BaseModel):
    organization_name: str = Field(..., min_length=2, max_length=255, description="Tenant/Company name")
    email: EmailStr = Field(..., description="User corporate email")
    password: str = Field(..., min_length=8, max_length=128, description="Strong password (min 8 characters)")
    role: Role | None = Field(default=Role.TENANT_ADMIN, description="Role within the tenant")


class UserLogin(BaseModel):
    email: EmailStr = Field(..., description="Registered email address")
    password: str = Field(..., min_length=1, description="Password")


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserRead


class TokenRefreshRequest(BaseModel):
    refresh_token: str = Field(..., min_length=10, description="Valid signed refresh token")


class TokenRefreshResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class LogoutResponse(BaseModel):
    message: str = "Successfully logged out."


class TokenPayload(BaseModel):
    sub: uuid.UUID
    tenant_id: uuid.UUID
    email: str
    role: str
    exp: int
    iat: int
