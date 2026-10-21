import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_tenant_scoped_asset_creation(client: AsyncClient):
    """Verifies that an asset is created and strictly attached to the user's tenant."""
    reg_res = await client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Asset Test Corp",
            "email": "engineer@assetcorp.com",
            "password": "Password123!",
            "role": "SECURITY_ENGINEER",
        },
    )
    token = reg_res.json()["access_token"]
    expected_tenant_id = reg_res.json()["user"]["tenant_id"]

    asset_payload = {
        "hostname": "prod-db-01.aegis.internal",
        "ip_address": "10.0.1.15",
        "asset_type": "SERVER",
        "criticality": "HIGH",
        "environment": "PRODUCTION",
        "status": "ACTIVE",
    }

    create_res = await client.post(
        "/api/v1/assets",
        headers={"Authorization": f"Bearer {token}"},
        json=asset_payload,
    )
    assert create_res.status_code == 201
    asset_data = create_res.json()
    assert asset_data["hostname"] == "prod-db-01.aegis.internal"
    assert asset_data["tenant_id"] == expected_tenant_id


@pytest.mark.asyncio
async def test_client_cannot_spoof_tenant_id_in_asset_creation(client: AsyncClient):
    """
    Verifies Security Rule 6: Never trust tenant_id supplied directly by the client.
    Even if a malicious client injects a rogue tenant_id in body, the server enforces its own tenant_id.
    """
    reg_res = await client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Authentic Tenant",
            "email": "admin@authentictenant.com",
            "password": "Password123!",
            "role": "TENANT_ADMIN",
        },
    )
    token = reg_res.json()["access_token"]
    authentic_tenant_id = reg_res.json()["user"]["tenant_id"]

    spoofed_payload = {
        "tenant_id": "00000000-0000-0000-0000-000000000000",
        "hostname": "workstation-05.corp",
        "ip_address": "192.168.1.105",
        "asset_type": "WORKSTATION",
        "criticality": "LOW",
        "environment": "LAB",
    }

    create_res = await client.post(
        "/api/v1/assets",
        headers={"Authorization": f"Bearer {token}"},
        json=spoofed_payload,
    )
    assert create_res.status_code == 201
    asset_data = create_res.json()
    assert asset_data["tenant_id"] == authentic_tenant_id
    assert asset_data["tenant_id"] != "00000000-0000-0000-0000-000000000000"


@pytest.mark.asyncio
async def test_asset_creation_invalid_input_validation(client: AsyncClient):
    """Verifies that invalid asset inputs (empty hostname or missing required fields) fail with 422."""
    reg_res = await client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Validation Test Org",
            "email": "admin@validationtest.com",
            "password": "Password123!",
            "role": "TENANT_ADMIN",
        },
    )
    token = reg_res.json()["access_token"]

    bad_payload = {
        "hostname": "",  # Min length violation
        "ip_address": "123",  # Too short for IP
    }
    res = await client.post(
        "/api/v1/assets",
        headers={"Authorization": f"Bearer {token}"},
        json=bad_payload,
    )
    assert res.status_code == 422
