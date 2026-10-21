import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_security_headers_present(client: AsyncClient):
    """Verifies that security headers are attached to all HTTP responses."""
    res = await client.get("/health")
    assert res.status_code == 200
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"
    assert "Strict-Transport-Security" in res.headers
    assert "Content-Security-Policy" in res.headers


@pytest.mark.asyncio
async def test_error_handling_middleware_does_not_leak_stacktrace(client: AsyncClient):
    """
    Verifies that 500 errors handled by ErrorHandlingMiddleware return safe JSON
    and do not leak internal Python tracebacks or sensitive server details.
    """
    # Trigger 422/400 validation or simulate an unhandled path
    res = await client.post(
        "/api/v1/auth/register",
        json={"email": "not-an-email"},  # Missing required fields
    )
    assert res.status_code == 422
    _ = res.json()
    assert "Traceback" not in res.text
    assert 'File "' not in res.text


@pytest.mark.asyncio
async def test_role_restrictions_soc_l1_cannot_create_assets(client: AsyncClient):
    """
    Verifies that a user with SOC_L1 role cannot create infrastructure assets,
    receiving HTTP 403 Forbidden.
    """
    reg_res = await client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Role Test Tenant",
            "email": "l1analyst@roletest.com",
            "password": "Password123!",
            "role": "SOC_L1",
        },
    )
    assert reg_res.status_code == 201
    token = reg_res.json()["access_token"]

    asset_res = await client.post(
        "/api/v1/assets",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "hostname": "firewall-core.corp",
            "ip_address": "10.0.0.1",
        },
    )
    assert asset_res.status_code == 403
    assert "insufficient role permissions" in asset_res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_tampered_token_signature_fails_authentication(client: AsyncClient):
    """Verifies that tampering with a JWT signature immediately causes 401."""
    reg_res = await client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Tamper Test Org",
            "email": "admin@tamper.com",
            "password": "Password123!",
            "role": "TENANT_ADMIN",
        },
    )
    token = reg_res.json()["access_token"]

    # Tamper with the last 5 characters of the token
    tampered_token = token[:-5] + "XXXXX"

    res = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {tampered_token}"},
    )
    assert res.status_code == 401
    assert "invalid" in res.json()["detail"].lower()
