import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_tenant_creation_by_admin(client: AsyncClient):
    """Verifies that an authenticated TENANT_ADMIN can provision a new tenant."""
    # Register an admin
    reg_res = await client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Admin Tenant Co",
            "email": "ciso@admintenant.com",
            "password": "Password123!",
            "role": "CISO",
        },
    )
    token = reg_res.json()["access_token"]

    # Create another tenant
    create_res = await client.post(
        "/api/v1/tenants",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "Subsidiary Tenant Alpha"},
    )
    assert create_res.status_code == 201
    tenant_data = create_res.json()
    assert tenant_data["name"] == "Subsidiary Tenant Alpha"
    assert tenant_data["status"] == "ACTIVE"


@pytest.mark.asyncio
async def test_tenant_creation_forbidden_for_soc_l1(client: AsyncClient):
    """Verifies that a low-privilege SOC_L1 role cannot provision tenants (403 Forbidden)."""
    reg_res = await client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Standard Tenant",
            "email": "analyst1@standard.com",
            "password": "Password123!",
            "role": "SOC_L1",
        },
    )
    token = reg_res.json()["access_token"]

    create_res = await client.post(
        "/api/v1/tenants",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "Unauthorized Tenant Attempt"},
    )
    assert create_res.status_code == 403
    assert "insufficient role permissions" in create_res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_get_current_tenant_me(client: AsyncClient):
    """Verifies that /api/v1/tenants/me returns caller's tenant organization details."""
    reg_res = await client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Cyber Operations HQ",
            "email": "manager@cyberhq.com",
            "password": "Password123!",
            "role": "SECURITY_MANAGER",
        },
    )
    token = reg_res.json()["access_token"]

    me_res = await client.get(
        "/api/v1/tenants/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me_res.status_code == 200
    tenant_info = me_res.json()
    assert tenant_info["name"] == "Cyber Operations HQ"
