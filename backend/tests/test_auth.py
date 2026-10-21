import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_user_registration_success(client: AsyncClient):
    """Verifies successful user registration and tenant assignment."""
    payload = {
        "organization_name": "Acme Cyber Defense Corp",
        "email": "admin@acmecyber.com",
        "password": "SuperSecurePassword123!",
        "role": "TENANT_ADMIN",
    }
    response = await client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["email"] == "admin@acmecyber.com"
    assert data["user"]["role"] == "TENANT_ADMIN"
    assert "tenant_id" in data["user"]


@pytest.mark.asyncio
async def test_duplicate_registration_fails(client: AsyncClient):
    """Verifies that registering an existing email fails with 400 Bad Request."""
    payload = {
        "organization_name": "CyberShield Ltd",
        "email": "duplicate@cybershield.com",
        "password": "Password123!",
        "role": "TENANT_ADMIN",
    }
    first_res = await client.post("/api/v1/auth/register", json=payload)
    assert first_res.status_code == 201

    second_res = await client.post("/api/v1/auth/register", json=payload)
    assert second_res.status_code == 400
    assert "already exists" in second_res.json()["detail"]


@pytest.mark.asyncio
async def test_user_login_success(client: AsyncClient):
    """Verifies user login with valid credentials."""
    email = "analyst@soc.corp"
    password = "CorrectHorseBatteryStaple99!"
    reg_payload = {
        "organization_name": "SOC Corp",
        "email": email,
        "password": password,
        "role": "SOC_L1",
    }
    await client.post("/api/v1/auth/register", json=reg_payload)

    login_payload = {
        "email": email,
        "password": password,
    }
    response = await client.post("/api/v1/auth/login", json=login_payload)
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["user"]["email"] == email


@pytest.mark.asyncio
async def test_authentication_failure_wrong_password(client: AsyncClient):
    """Verifies authentication failure returns 401 Unauthorized for incorrect password."""
    email = "target@corp.internal"
    password = "OriginalPassword123!"
    await client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Corp Internal",
            "email": email,
            "password": password,
            "role": "SOC_L1",
        },
    )

    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "WrongPasswordAttempt!"},
    )
    assert login_res.status_code == 401
    assert "Invalid email or password" in login_res.json()["detail"]


@pytest.mark.asyncio
async def test_authentication_failure_nonexistent_user(client: AsyncClient):
    """Verifies 401 Unauthorized when attempting to login with an unknown email."""
    login_res = await client.post(
        "/api/v1/auth/login",
        json={"email": "nobody@nowhere.com", "password": "AnyPassword123!"},
    )
    assert login_res.status_code == 401


@pytest.mark.asyncio
async def test_get_current_user_profile(client: AsyncClient):
    """Verifies that /api/v1/auth/me returns the authenticated user profile."""
    reg_res = await client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Auth Me Org",
            "email": "engineer@authme.com",
            "password": "Password12345!",
            "role": "SECURITY_ENGINEER",
        },
    )
    token = reg_res.json()["access_token"]

    me_res = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me_res.status_code == 200
    me_data = me_res.json()
    assert me_data["email"] == "engineer@authme.com"
    assert me_data["role"] == "SECURITY_ENGINEER"


@pytest.mark.asyncio
async def test_missing_authentication_fails(client: AsyncClient):
    """Verifies that calling a protected route without token returns 401."""
    res = await client.get("/api/v1/auth/me")
    assert res.status_code == 401
    assert "token is missing" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_invalid_jwt_fails(client: AsyncClient):
    """Verifies that sending a forged/garbage JWT returns 401."""
    res = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer totally.invalid.forgedtoken"},
    )
    assert res.status_code == 401
    assert "invalid" in res.json()["detail"].lower()
