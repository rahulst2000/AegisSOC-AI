import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_tenant_scoped_event_ingestion(client: AsyncClient):
    """Verifies that ingested telemetry events are attached to the tenant and persisted."""
    reg_res = await client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Telemetry Org",
            "email": "soc@telemetryorg.com",
            "password": "Password123!",
            "role": "SOC_L1",
        },
    )
    token = reg_res.json()["access_token"]
    tenant_id = reg_res.json()["user"]["tenant_id"]

    event_payload = {
        "source": "CrowdStrike-Falcon",
        "event_type": "SUSPICIOUS_POWERSHELL_INVOCATION",
        "severity": "HIGH",
        "source_ip": "192.168.10.42",
        "username": "victim.user",
        "hostname": "win11-finance-03",
        "raw_event": {
            "ProcessCommandLine": "powershell.exe -enc SQBFAFgA...",
            "ParentProcess": "explorer.exe",
            "PID": 4092,
        },
    }

    res = await client.post(
        "/api/v1/events",
        headers={"Authorization": f"Bearer {token}"},
        json=event_payload,
    )
    assert res.status_code == 201
    event_data = res.json()
    assert event_data["tenant_id"] == tenant_id
    assert event_data["event_type"] == "SUSPICIOUS_POWERSHELL_INVOCATION"
    assert event_data["severity"] == "HIGH"
    assert "normalized_event" in event_data


@pytest.mark.asyncio
async def test_high_severity_event_generates_alert(client: AsyncClient):
    """Verifies that HIGH/CRITICAL events automatically generate an Alert."""
    reg_res = await client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Alert Detection Org",
            "email": "lead@detection.internal",
            "password": "Password123!",
            "role": "SOC_L2",
        },
    )
    token = reg_res.json()["access_token"]

    # Ingest CRITICAL event
    event_res = await client.post(
        "/api/v1/events",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "source": "PaloAlto-Firewall",
            "event_type": "C2_BEACONING_DETECTED",
            "severity": "CRITICAL",
            "source_ip": "10.0.5.21",
            "raw_event": {"dest_ip": "198.51.100.12", "dest_port": 443},
        },
    )
    assert event_res.status_code == 201

    # Query alerts endpoint
    alerts_res = await client.get(
        "/api/v1/alerts",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert alerts_res.status_code == 200
    alerts = alerts_res.json()
    assert len(alerts) >= 1
    assert any("C2_BEACONING_DETECTED" in a["detection_rule"] for a in alerts)
