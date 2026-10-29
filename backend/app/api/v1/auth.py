from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.models.user import User
from app.schemas.auth import (
    LogoutResponse,
    Token,
    TokenRefreshRequest,
    TokenRefreshResponse,
    UserLogin,
    UserRegister,
)
from app.schemas.user import UserRead
from app.services.auth_service import (
    authenticate_user,
    logout_user,
    refresh_user_token,
    register_user,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=Token, status_code=status.HTTP_201_CREATED)
async def register(
    register_data: UserRegister,
    db: AsyncSession = Depends(get_db),
):
    """
    Onboards a new organization or user, issuing authenticated JWT tokens.
    """
    return await register_user(db=db, register_data=register_data)


@router.post("/login", response_model=Token, status_code=status.HTTP_200_OK)
async def login(
    login_data: UserLogin,
    db: AsyncSession = Depends(get_db),
):
    """
    Authenticates existing users with constant-time password verification.
    """
    return await authenticate_user(db=db, login_data=login_data)


@router.post("/refresh", response_model=TokenRefreshResponse, status_code=status.HTTP_200_OK)
async def refresh_token(
    refresh_req: TokenRefreshRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Exchanges a valid refresh token for a fresh access token and rotated refresh token.
    Fails securely with HTTP 401 if refresh token is invalid or expired.
    """
    return await refresh_user_token(db=db, refresh_token_str=refresh_req.refresh_token)


@router.post("/logout", response_model=LogoutResponse, status_code=status.HTTP_200_OK)
async def logout(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Terminates active session and records security audit trail.
    """
    return await logout_user(db=db, user=current_user)


@router.get("/me", response_model=UserRead, status_code=status.HTTP_200_OK)
async def get_me(
    current_user: User = Depends(get_current_user),
):
    """
    Returns the currently authenticated user's profile and active tenant context.
    """
    return current_user
