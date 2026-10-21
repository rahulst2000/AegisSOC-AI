from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.models.user import User
from app.schemas.auth import Token, UserLogin, UserRegister
from app.schemas.user import UserRead
from app.services.auth_service import authenticate_user, register_user

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


@router.get("/me", response_model=UserRead, status_code=status.HTTP_200_OK)
async def get_me(
    current_user: User = Depends(get_current_user),
):
    """
    Returns the currently authenticated user's profile and active tenant context.
    """
    return current_user
