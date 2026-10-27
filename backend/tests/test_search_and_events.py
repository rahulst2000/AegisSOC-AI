import uuid

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_global_threat_search_and_tenant_isolation(client: AsyncClient):
    """
    Verifies that global threat search queries across all security entity categories
    and maintains strict multi-tenant boundary isolation.
    """
    # 1. Register Tenant A
    reg_a = await client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Global Search Org A",
            "email": "analyst_a@searchorga.com",
            "password": "Password123!",
            "role": "SOC_L2",
        },
    )
    assert reg_a.status_code == 201
    token_a = reg_a.json()["access_token"]

    # 2. Register Tenant B
    reg_b = await client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Global Search Org B",
            "email": "analyst_b@searchorgb.com",
            "password": "Password123!",
            "role": "SOC_L2",
        },
    )
    assert reg_b.status_code == 201
    token_b = reg_b.json()["access_token"]

    # 3. Create Event, Incident, and Asset in Tenant A
    shared_ioc = "198.51.100.77"

    # Ingest Event in Tenant A
    evt_res = await client.post(
        "/api/v1/events",
        headers={"Authorization": f"Bearer {token_a}"},
        json={
            "source": "CrowdStrike-EDR",
            "event_type": "C2_BEACONING_ATTEMPT",
            "severity": "CRITICAL",
            "source_ip": shared_ioc,
            "hostname": "workstation-alpha",
            "username": "compromised_user",
            "raw_event": {"ioc": shared_ioc},
        },
    )
    assert evt_res.status_code == 201

    # Create Incident in Tenant A
    inc_res = await client.post(
        "/api/v1/incidents",
        headers={"Authorization": f"Bearer {token_a}"},
        json={
            "title": f"Active Command and Control Beaconing to {shared_ioc}",
            "description": "Cobalt Strike beaconing detected from finance workstation.",
            "severity": "CRITICAL",
            "risk_score": 92.5,
            "confidence": 0.98,
            "status": "OPEN",
        },
    )
    assert inc_res.status_code == 201

    # Create Asset in Tenant A
    ast_res = await client.post(
        "/api/v1/assets",
        headers={"Authorization": f"Bearer {token_a}"},
        json={
            "hostname": "workstation-alpha",
            "ip_address": shared_ioc,
            "asset_type": "WORKSTATION",
            "criticality": "HIGH",
            "environment": "PRODUCTION",
        },
    )
    assert ast_res.status_code == 201

    # 4. Search as Tenant A
    res_a = await client.get(
        f"/api/v1/search?q={shared_ioc}",
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert res_a.status_code == 200
    data_a = res_a.json()
    assert data_a["total_matches"] >= 3
    cats_a = data_a["categories"]
    assert any(e["source_ip"] == shared_ioc for e in cats_a["events"])
    assert any(shared_ioc in i["title"] for i in cats_a["incidents"])
    assert any(a["ip_address"] == shared_ioc for a in cats_a["assets"])

    # 5. Search as Tenant B - Isolation test (must return 0 matches for Tenant A's private IOCs)
    res_b = await client.get(
        f"/api/v1/search?q={shared_ioc}",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert res_b.status_code == 200
    data_b = res_b.json()
    assert len(data_b["categories"]["events"]) == 0
    assert len(data_b["categories"]["incidents"]) == 0
    assert len(data_b["categories"]["assets"]) == 0


@pytest.mark.asyncio
async def test_events_filtering_and_single_lookup(client: AsyncClient):
    """
    Verifies that the /events endpoint filters by severity, source, and search terms,
    and supports retrieving a single event by ID.
    """
    reg = await client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Event Filter Org",
            "email": "operator@filterorg.com",
            "password": "Password123!",
            "role": "SOC_L1",
        },
    )
    assert reg.status_code == 201
    token = reg.json()["access_token"]

    # Ingest critical event
    crit_res = await client.post(
        "/api/v1/events",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "source": "paloalto",
            "event_type": "SQL_INJECTION",
            "severity": "CRITICAL",
            "source_ip": "192.168.100.5",
            "username": "db_admin",
            "hostname": "database-01",
            "raw_event": {"query": "' OR '1'='1"},
        },
    )
    assert crit_res.status_code == 201
    evt_crit_id = crit_res.json()["id"]

    # Ingest informational event
    info_res = await client.post(
        "/api/v1/events",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "source": "suricata",
            "event_type": "DNS_QUERY",
            "severity": "INFORMATIONAL",
            "source_ip": "192.168.100.6",
            "username": "regular_user",
            "hostname": "client-01",
            "raw_event": {"query": "corp.internal"},
        },
    )
    assert info_res.status_code == 201

    # Filter by severity
    res_crit = await client.get(
        "/api/v1/events?severity=CRITICAL",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res_crit.status_code == 200
    items_crit = res_crit.json()
    assert len(items_crit) == 1
    assert items_crit[0]["event_type"] == "SQL_INJECTION"

    # Filter by search term
    res_search = await client.get(
        "/api/v1/events?search=suricata",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res_search.status_code == 200
    items_search = res_search.json()
    assert len(items_search) == 1
    assert items_search[0]["event_type"] == "DNS_QUERY"

    # Lookup by single ID
    res_single = await client.get(
        f"/api/v1/events/{evt_crit_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res_single.status_code == 200
    assert res_single.json()["id"] == evt_crit_id

    # Lookup invalid ID
    res_404 = await client.get(
        f"/api/v1/events/{uuid.uuid4()}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res_404.status_code == 404
