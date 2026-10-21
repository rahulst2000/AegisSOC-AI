import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_cross_tenant_incident_access_denied(client: AsyncClient):
    """
    DEDICATED SECURITY TEST:
    Demonstrates that Tenant A user creates an incident, and Tenant B user attempts to
    retrieve Tenant A's incident directly by its ID.
    Expected result: HTTP 404 (preventing oracle enumeration & denying cross-tenant disclosure).
    """
    # 1. Onboard Tenant A and create a sensitive incident
    reg_a = await client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Tenant Alpha Defense Systems",
            "email": "lead@tenant-alpha.com",
            "password": "AlphaPassword123!",
            "role": "SOC_L2",
        },
    )
    assert reg_a.status_code == 201
    token_a = reg_a.json()["access_token"]
    tenant_a_id = reg_a.json()["user"]["tenant_id"]

    inc_a_res = await client.post(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {token_a}"},
        json={
            "title": "TOP SECRET: Advanced Persistent Threat Infiltration",
            "description": "Evidence of nation-state actor exfiltrating intellectual property.",
            "severity": "CRITICAL",
            "risk_score": 99.0,
            "confidence": 1.0,
            "status": "INVESTIGATING",
        },
    )
    assert inc_a_res.status_code == 201
    incident_a_id = inc_a_res.json()["id"]

    # 2. Onboard Tenant B (completely separate organization)
    reg_b = await client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Tenant Beta Logistics",
            "email": "analyst@tenant-beta.com",
            "password": "BetaPassword123!",
            "role": "SOC_L1",
        },
    )
    assert reg_b.status_code == 201
    token_b = reg_b.json()["access_token"]
    tenant_b_id = reg_b.json()["user"]["tenant_id"]
    assert tenant_a_id != tenant_b_id

    # 3. Tenant B user attempts to retrieve Tenant A's incident
    cross_access_res = await client.get(
        f"/api/v1/incidents/{incident_a_id}",
        headers={"Authorization": f"Bearer {token_b}"},
    )

    # 4. Assert cross-tenant access is strictly denied (HTTP 404)
    assert cross_access_res.status_code == 404
    assert "not found" in cross_access_res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_cross_tenant_asset_isolation(client: AsyncClient):
    """
    SECURITY TEST:
    Tenant A registers assets.
    Tenant B queries assets list.
    Tenant B must see 0 of Tenant A's assets.
    """
    # Tenant A registers and adds an asset
    reg_a = await client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Alpha Corp Inc",
            "email": "admin@alphacorp.com",
            "password": "Password123!",
            "role": "TENANT_ADMIN",
        },
    )
    token_a = reg_a.json()["access_token"]

    await client.post(
        "/api/v1/assets",
        headers={"Authorization": f"Bearer {token_a}"},
        json={
            "hostname": "alpha-classified-vault.internal",
            "ip_address": "10.50.0.1",
            "asset_type": "SERVER",
            "criticality": "CRITICAL",
            "environment": "PRODUCTION",
        },
    )

    # Tenant B registers
    reg_b = await client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Beta Industries",
            "email": "admin@betaindustries.com",
            "password": "Password123!",
            "role": "TENANT_ADMIN",
        },
    )
    token_b = reg_b.json()["access_token"]

    # Tenant B lists assets
    res_b = await client.get(
        "/api/v1/assets",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert res_b.status_code == 200
    assets_b = res_b.json()

    # Tenant B must NOT see Alpha's asset
    assert len(assets_b) == 0
    assert not any(a["hostname"] == "alpha-classified-vault.internal" for a in assets_b)


@pytest.mark.asyncio
async def test_cross_tenant_event_isolation(client: AsyncClient):
    """
    SECURITY TEST:
    Tenant A ingests security events.
    Tenant B queries events.
    Tenant B must NOT receive any events belonging to Tenant A.
    """
    # Tenant A ingests event
    reg_a = await client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Alpha Security Unit",
            "email": "engineer@alphasec.org",
            "password": "Password123!",
            "role": "SECURITY_ENGINEER",
        },
    )
    token_a = reg_a.json()["access_token"]

    await client.post(
        "/api/v1/events",
        headers={"Authorization": f"Bearer {token_a}"},
        json={
            "source": "EDR",
            "event_type": "CONFIDENTIAL_EXFILTRATION_EVENT",
            "severity": "CRITICAL",
            "source_ip": "172.16.1.5",
            "raw_event": {"details": "Secret exfiltration attempt"},
        },
    )

    # Tenant B queries events
    reg_b = await client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Beta Security Unit",
            "email": "engineer@betasec.org",
            "password": "Password123!",
            "role": "SECURITY_ENGINEER",
        },
    )
    token_b = reg_b.json()["access_token"]

    res_b = await client.get(
        "/api/v1/events",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert res_b.status_code == 200
    events_b = res_b.json()
    assert len(events_b) == 0
    assert not any(e["event_type"] == "CONFIDENTIAL_EXFILTRATION_EVENT" for e in events_b)


@pytest.mark.asyncio
async def test_cross_tenant_alerts_isolation(client: AsyncClient):
    """
    SECURITY TEST:
    Tenant A triggers an alert through critical event ingestion.
    Tenant B queries alerts.
    Tenant B must see 0 alerts.
    """
    reg_a = await client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Alpha Alert Org",
            "email": "analyst@alphaalert.com",
            "password": "Password123!",
            "role": "SOC_L1",
        },
    )
    token_a = reg_a.json()["access_token"]

    await client.post(
        "/api/v1/events",
        headers={"Authorization": f"Bearer {token_a}"},
        json={
            "source": "WAF",
            "event_type": "SQL_INJECTION_ATTACK",
            "severity": "CRITICAL",
            "raw_event": {"query": "' OR 1=1 --"},
        },
    )

    # Tenant B lists alerts
    reg_b = await client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Beta Alert Org",
            "email": "analyst@betaalert.com",
            "password": "Password123!",
            "role": "SOC_L1",
        },
    )
    token_b = reg_b.json()["access_token"]

    res_b = await client.get(
        "/api/v1/alerts",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert res_b.status_code == 200
    assert len(res_b.json()) == 0
