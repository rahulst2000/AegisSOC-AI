import uuid

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_create_and_fetch_incident(client: AsyncClient):
    """Verifies incident creation and fetching for the tenant."""
    reg_res = await client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Incident Mgmt Org",
            "email": "manager@incidentmgmt.com",
            "password": "Password123!",
            "role": "SECURITY_MANAGER",
        },
    )
    token = reg_res.json()["access_token"]
    tenant_id = reg_res.json()["user"]["tenant_id"]

    inc_payload = {
        "title": "Active Ransomware Propagation Attempt",
        "description": "Suspected LockBit variant detected on finance subnet host.",
        "severity": "CRITICAL",
        "risk_score": 92.5,
        "confidence": 0.98,
        "status": "INVESTIGATING",
    }
    create_res = await client.post(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {token}"},
        json=inc_payload,
    )
    assert create_res.status_code == 201
    created_inc = create_res.json()
    assert created_inc["tenant_id"] == tenant_id
    assert created_inc["title"] == "Active Ransomware Propagation Attempt"

    # Fetch by ID
    get_res = await client.get(
        f"/api/v1/incidents/{created_inc['id']}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert get_res.status_code == 200
    assert get_res.json()["id"] == created_inc["id"]


@pytest.mark.asyncio
async def test_fetch_nonexistent_incident_returns_404(client: AsyncClient):
    """Verifies that requesting an unmapped incident ID returns 404."""
    reg_res = await client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Search Test Org",
            "email": "analyst@searchtest.com",
            "password": "Password123!",
            "role": "SOC_L1",
        },
    )
    token = reg_res.json()["access_token"]

    random_id = uuid.uuid4()
    res = await client.get(
        f"/api/v1/incidents/{random_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()
