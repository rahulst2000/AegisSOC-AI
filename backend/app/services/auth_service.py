from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.tenant import Tenant
from app.models.user import User
from app.schemas.auth import Token, UserLogin, UserRegister
from app.schemas.user import UserRead
from app.security.hashing import hash_password, verify_password
from app.security.roles import Role
from app.security.tokens import create_access_token, create_refresh_token
from app.services.audit_service import log_audit_event


async def register_user(db: AsyncSession, register_data: UserRegister) -> Token:
    """
    Registers a new tenant and/or user in an isolated manner.
    Creates initial organization if not already existing, and assigns the specified role.
    """
    # 1. Check if user email already exists across the system
    result = await db.execute(select(User).where(User.email == register_data.email))
    existing_user = result.scalar_one_or_none()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email address already exists.",
        )

    # 2. Find or create the tenant organization
    result = await db.execute(select(Tenant).where(Tenant.name == register_data.organization_name))
    tenant = result.scalar_one_or_none()
    if not tenant:
        tenant = Tenant(
            name=register_data.organization_name,
            status="ACTIVE",
        )
        db.add(tenant)
        await db.flush()

    # 3. Hash password with bcrypt
    hashed_pwd = hash_password(register_data.password)

    # 4. Create user record
    role_to_assign = register_data.role or Role.TENANT_ADMIN
    user = User(
        tenant_id=tenant.id,
        email=register_data.email,
        password_hash=hashed_pwd,
        role=role_to_assign.value if isinstance(role_to_assign, Role) else str(role_to_assign),
        status="ACTIVE",
    )
    db.add(user)
    await db.flush()

    # 5. Log audit trail
    await log_audit_event(
        db=db,
        tenant_id=tenant.id,
        user_id=user.id,
        action="USER_REGISTRATION",
        resource_type="USER",
        resource_id=str(user.id),
        result="SUCCESS",
        metadata={"email": user.email, "role": user.role},
    )

    await db.commit()
    await db.refresh(user)

    # 6. Generate JWT tokens
    access_token = create_access_token(
        user_id=user.id,
        tenant_id=tenant.id,
        email=user.email,
        role=user.role,
    )
    refresh_token = create_refresh_token(
        user_id=user.id,
        tenant_id=tenant.id,
    )

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        user=UserRead.model_validate(user),
    )


async def authenticate_user(db: AsyncSession, login_data: UserLogin) -> Token:
    """
    Authenticates a user by email and password, issuing access and refresh tokens.
    Fails securely with a generic 401 message on either wrong email or wrong password.
    """
    result = await db.execute(select(User).where(User.email == login_data.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(login_data.password, user.password_hash):
        if user:
            # Audit failed attempt for tenant
            await log_audit_event(
                db=db,
                tenant_id=user.tenant_id,
                user_id=user.id,
                action="AUTH_LOGIN",
                resource_type="USER",
                resource_id=str(user.id),
                result="FAILURE",
                metadata={"reason": "Invalid credentials", "email": login_data.email},
            )
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if user.status != "ACTIVE":
        await log_audit_event(
            db=db,
            tenant_id=user.tenant_id,
            user_id=user.id,
            action="AUTH_LOGIN",
            resource_type="USER",
            resource_id=str(user.id),
            result="DENIED",
            metadata={"reason": f"Account status is {user.status}"},
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"User account is {user.status.lower()}.",
        )

    # Successful login audit
    await log_audit_event(
        db=db,
        tenant_id=user.tenant_id,
        user_id=user.id,
        action="AUTH_LOGIN",
        resource_type="USER",
        resource_id=str(user.id),
        result="SUCCESS",
        metadata={"role": user.role},
    )
    await db.commit()

    access_token = create_access_token(
        user_id=user.id,
        tenant_id=user.tenant_id,
        email=user.email,
        role=user.role,
    )
    refresh_token = create_refresh_token(
        user_id=user.id,
        tenant_id=user.tenant_id,
    )

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        user=UserRead.model_validate(user),
    )
