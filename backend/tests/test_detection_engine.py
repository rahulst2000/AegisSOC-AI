import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.detection.engine import DetectionEngine
from app.detection.rule_loader import sync_rules_to_db
from app.models.event import SecurityEvent
from app.models.tenant import Tenant


@pytest.mark.asyncio
async def test_scenario_a_ssh_bruteforce(db_session: AsyncSession):
    """
    Scenario A: 10 failed SSH logins from one IP.
    Expected: Brute-force detection generated, evidence linked, MITRE T1110.001 mapped.
    """
    # 1. Setup tenant & sync rules
    tenant = Tenant(name="BruteForce Victim Corp")
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)

    await sync_rules_to_db(db_session)

    # 2. Ingest 10 failed SSH logins from single IP
    attacker_ip = "198.51.100.45"
    events: list[SecurityEvent] = []
    base_time = datetime.now(UTC)

    for i in range(10):
        evt = SecurityEvent(
            tenant_id=tenant.id,
            timestamp=base_time + timedelta(seconds=i * 5),
            source="ssh",
            event_type="AUTH_FAILURE",
            severity="LOW",
            source_ip=attacker_ip,
            username="root",
            hostname="bastion-01",
            raw_event={"msg": "Failed password for root", "ip": attacker_ip},
            normalized_event={"event": {"type": "auth_failure"}, "source": {"ip": attacker_ip}},
        )
        db_session.add(evt)
        events.append(evt)

    await db_session.commit()

    # 3. Evaluate events with DetectionEngine
    engine = DetectionEngine()
    detections = await engine.evaluate_events(db=db_session, tenant_id=tenant.id, events=events)

    # 4. Assertions
    assert len(detections) >= 1
    bf_detection = next((d for d in detections if "SSH" in d.title or "BRUTEFORCE" in d.rule_id), None)
    assert bf_detection is not None
    assert bf_detection.tenant_id == tenant.id
    assert bf_detection.severity in {"HIGH", "CRITICAL"}
    assert "T1110.001" in bf_detection.mitre_techniques or "T1110" in bf_detection.mitre_techniques
    assert len(bf_detection.event_ids) == 10
    # Verifiable evidence: check event IDs match actual events
    actual_ids = {str(e.id) for e in events}
    assert set(bf_detection.event_ids) == actual_ids


@pytest.mark.asyncio
async def test_scenario_b_password_spraying(db_session: AsyncSession):
    """
    Scenario B: Multiple usernames from one IP (5 distinct users failing from single IP).
    Expected: Password-spraying detection generated, MITRE T1110.003 mapped.
    """
    tenant = Tenant(name="Spray Victim Org")
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)

    await sync_rules_to_db(db_session)

    attacker_ip = "203.0.113.88"
    usernames = ["alice", "bob", "carol", "david", "eve"]
    events: list[SecurityEvent] = []
    base_time = datetime.now(UTC)

    for idx, user in enumerate(usernames):
        evt = SecurityEvent(
            tenant_id=tenant.id,
            timestamp=base_time + timedelta(seconds=idx * 10),
            source="ldap",
            event_type="AUTH_FAILURE",
            severity="LOW",
            source_ip=attacker_ip,
            username=user,
            hostname="ad-dc-01",
            raw_event={"msg": f"Auth failed for {user}", "ip": attacker_ip},
            normalized_event={"event": {"type": "auth_failure"}, "source": {"ip": attacker_ip}, "user": {"name": user}},
        )
        db_session.add(evt)
        events.append(evt)

    await db_session.commit()

    engine = DetectionEngine()
    detections = await engine.evaluate_events(db=db_session, tenant_id=tenant.id, events=events)

    spray_detection = next((d for d in detections if "SPRAYING" in d.rule_id or "Spray" in d.title), None)
    assert spray_detection is not None
    assert spray_detection.tenant_id == tenant.id
    assert "T1110.003" in spray_detection.mitre_techniques or "T1110" in spray_detection.mitre_techniques
    assert len(spray_detection.event_ids) >= 5


@pytest.mark.asyncio
async def test_scenario_c_failure_then_success(db_session: AsyncSession):
    """
    Scenario C: Repeated failures followed by successful login.
    Expected: Failure-then-success detection triggered.
    """
    tenant = Tenant(name="Account Breach Org")
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)

    await sync_rules_to_db(db_session)

    attacker_ip = "192.0.2.14"
    events: list[SecurityEvent] = []
    base_time = datetime.now(UTC)

    # 2 failures
    for i in range(2):
        evt = SecurityEvent(
            tenant_id=tenant.id,
            timestamp=base_time + timedelta(seconds=i * 5),
            source="auth_service",
            event_type="AUTH_FAILURE",
            severity="LOW",
            source_ip=attacker_ip,
            username="jsmith",
            hostname="vpn-gateway",
            raw_event={"msg": "Invalid password"},
            normalized_event={"event": {"type": "auth_failure"}},
        )
        db_session.add(evt)
        events.append(evt)

    # 1 success
    success_evt = SecurityEvent(
        tenant_id=tenant.id,
        timestamp=base_time + timedelta(seconds=20),
        source="auth_service",
        event_type="AUTH_SUCCESS",
        severity="INFO",
        source_ip=attacker_ip,
        username="jsmith",
        hostname="vpn-gateway",
        raw_event={"msg": "Login success"},
        normalized_event={"event": {"type": "auth_success"}},
    )
    db_session.add(success_evt)
    events.append(success_evt)

    await db_session.commit()

    engine = DetectionEngine()
    detections = await engine.evaluate_events(db=db_session, tenant_id=tenant.id, events=events)

    fts_detection = next((d for d in detections if "FAILURE-THEN-SUCCESS" in d.rule_id or "Repeated" in d.title), None)
    assert fts_detection is not None
    assert fts_detection.tenant_id == tenant.id
    assert "T1078" in fts_detection.mitre_techniques


@pytest.mark.asyncio
async def test_scenario_d_normal_single_login_no_bruteforce(db_session: AsyncSession):
    """
    Scenario D: Normal single successful login.
    Expected: No brute-force or spraying detection.
    """
    tenant = Tenant(name="Normal Org")
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)

    await sync_rules_to_db(db_session)

    evt = SecurityEvent(
        tenant_id=tenant.id,
        timestamp=datetime.now(UTC),
        source="ssh",
        event_type="AUTH_SUCCESS",
        severity="INFO",
        source_ip="10.0.0.50",
        username="developer",
        hostname="workstation-01",
        raw_event={"msg": "Accepted publickey for developer"},
        normalized_event={"event": {"type": "auth_success"}},
    )
    db_session.add(evt)
    await db_session.commit()

    engine = DetectionEngine()
    detections = await engine.evaluate_events(db=db_session, tenant_id=tenant.id, events=[evt])

    # Must NOT generate brute-force or spraying detection
    bf = [d for d in detections if "BRUTEFORCE" in d.rule_id or "SPRAYING" in d.rule_id]
    assert len(bf) == 0


@pytest.mark.asyncio
async def test_detection_rules_api_lifecycle(client: AsyncClient):
    """
    Verifies detection rules CRUD API:
    - Lists rules (system + tenant)
    - Creates tenant rule (RBAC enforced)
    - Updates tenant rule
    """
    # 1. Register security engineer
    reg_res = await client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Rules SecLab",
            "email": "engineer@ruleseclab.com",
            "password": "Password123!",
            "role": "SECURITY_ENGINEER",
        },
    )
    assert reg_res.status_code == 201
    token = reg_res.json()["access_token"]
    tenant_id = reg_res.json()["user"]["tenant_id"]

    headers = {"Authorization": f"Bearer {token}"}

    # 2. List rules
    list_res = await client.get("/api/v1/rules", headers=headers)
    assert list_res.status_code == 200
    assert isinstance(list_res.json(), list)

    # 3. Create a tenant-specific rule
    custom_rule = {
        "rule_id": f"CUSTOM-RULE-{uuid.uuid4().hex[:6].upper()}",
        "name": "Custom PowerShell Execution Detector",
        "description": "Flags encoded powershell execution in production containers.",
        "version": "1.0.0",
        "enabled": True,
        "severity": "HIGH",
        "confidence": 0.95,
        "event_types": ["PROCESS_CREATE"],
        "conditions": {
            "selections": {
                "process": {
                    "Image|endswith": "powershell.exe",
                    "CommandLine|contains": "-enc",
                }
            }
        },
        "mitre_tactics": ["Execution"],
        "mitre_techniques": ["T1059"],
        "tags": ["powershell", "encoded"],
    }
    create_res = await client.post("/api/v1/rules", headers=headers, json=custom_rule)
    assert create_res.status_code == 201
    created_rule = create_res.json()
    assert created_rule["rule_id"] == custom_rule["rule_id"]
    assert created_rule["tenant_id"] == tenant_id

    # 4. Update the rule
    patch_res = await client.patch(
        f"/api/v1/rules/{created_rule['rule_id']}",
        headers=headers,
        json={"severity": "CRITICAL", "confidence": 0.99},
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["severity"] == "CRITICAL"
    assert patch_res.json()["confidence"] == 0.99
