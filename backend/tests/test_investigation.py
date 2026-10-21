from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.detection.engine import DetectionEngine
from app.detection.rule_loader import sync_rules_to_db
from app.investigation.investigator import run_investigation
from app.models.event import SecurityEvent
from app.models.incident import Incident
from app.models.tenant import Tenant


@pytest.mark.asyncio
async def test_scenario_a_confirmed_bruteforce_investigation(
    db_session: AsyncSession,
    client: AsyncClient,
):
    """
    Scenario A: Confirmed brute-force incident.
    Expected: Investigation identifies credential attack (H1=CONFIRMED/LIKELY),
    recommends IP containment, grounds findings in actual event IDs.
    """
    tenant = Tenant(name="Investigate Tenant A")
    db_session.add(tenant)
    await db_session.flush()

    await sync_rules_to_db(db_session)

    # 1. Ingest 10 SSH brute-force failures from 198.51.100.25
    attacker_ip = "198.51.100.25"
    base_time = datetime.now(UTC) - timedelta(minutes=3)
    events: list[SecurityEvent] = []
    for i in range(10):
        evt = SecurityEvent(
            tenant_id=tenant.id,
            source="ssh",
            event_type="AUTH_FAILURE",
            severity="LOW",
            source_ip=attacker_ip,
            username="admin",
            hostname="auth-server-1",
            timestamp=base_time + timedelta(seconds=i * 10),
            raw_event={"msg": "Failed password for admin", "ip": attacker_ip},
            normalized_event={"event": {"type": "auth_failure"}, "source": {"ip": attacker_ip}},
        )
        db_session.add(evt)
        events.append(evt)
    await db_session.commit()

    engine = DetectionEngine()
    detections = await engine.evaluate_events(db=db_session, tenant_id=tenant.id, events=events)
    assert len(detections) >= 1

    # Create Incident
    incident = Incident(
        tenant_id=tenant.id,
        title="Correlated Incident: SSH Brute Force",
        description="SSH Brute force activity detected.",
        severity="HIGH",
        risk_score=75,
        confidence=0.95,
        status="OPEN",
        mitre_techniques=["T1110.001"],
        detection_ids=[str(d.id) for d in detections],
        affected_assets=["auth-server-1"],
        affected_users=["admin"],
        source_ips=["198.51.100.25"],
    )
    db_session.add(incident)
    await db_session.flush()

    # 2. Run Autonomous Investigation
    investigation = await run_investigation(
        db=db_session,
        tenant_id=tenant.id,
        incident_id=incident.id,
        force_refresh=True,
    )

    assert investigation is not None
    assert investigation.status == "COMPLETED"
    assert "198.51.100.25" in investigation.executive_summary or "credential" in investigation.executive_summary.lower()

    # Verify H1 (Credential Attack) is CONFIRMED
    h1 = next((h for h in investigation.hypotheses if h.hypothesis_id == "H1"), None)
    assert h1 is not None
    assert h1.status in ("CONFIRMED", "LIKELY")
    assert len(h1.evidence_ids) > 0

    # Verify findings are grounded in valid event IDs
    all_event_ids = {str(e.id) for e in events}
    for f in investigation.findings:
        for eid in f.evidence_ids:
            assert eid in all_event_ids


@pytest.mark.asyncio
async def test_scenario_b_failure_then_success_compromised_account(
    db_session: AsyncSession,
):
    """
    Scenario B: Repeated failures followed by successful login.
    Expected: Compromised-account hypothesis (H2) becomes CONFIRMED or LIKELY.
    """
    tenant = Tenant(name="Investigate Tenant B")
    db_session.add(tenant)
    await db_session.flush()
    await sync_rules_to_db(db_session)

    base_time = datetime.now(UTC) - timedelta(minutes=5)
    events: list[SecurityEvent] = []

    # 4 failures
    for i in range(4):
        evt = SecurityEvent(
            tenant_id=tenant.id,
            source="auth_service",
            event_type="AUTH_FAILURE",
            severity="LOW",
            source_ip="203.0.113.88",
            username="victim_user",
            hostname="web-proxy-1",
            timestamp=base_time + timedelta(seconds=i * 5),
            raw_event={"msg": "Invalid password", "ip": "203.0.113.88"},
            normalized_event={"event": {"type": "auth_failure"}, "source": {"ip": "203.0.113.88"}},
        )
        db_session.add(evt)
        events.append(evt)

    # 1 success
    succ_evt = SecurityEvent(
        tenant_id=tenant.id,
        source="auth_service",
        event_type="AUTH_SUCCESS",
        severity="INFO",
        source_ip="203.0.113.88",
        username="victim_user",
        hostname="web-proxy-1",
        timestamp=base_time + timedelta(seconds=40),
        raw_event={"msg": "Login success", "ip": "203.0.113.88"},
        normalized_event={"event": {"type": "auth_success"}, "source": {"ip": "203.0.113.88"}},
    )
    db_session.add(succ_evt)
    events.append(succ_evt)
    await db_session.commit()

    engine = DetectionEngine()
    detections = await engine.evaluate_events(db=db_session, tenant_id=tenant.id, events=events)

    incident = Incident(
        tenant_id=tenant.id,
        title="Account Takeover Chain: victim_user",
        description="Failures followed by successful login.",
        severity="CRITICAL",
        risk_score=90,
        confidence=0.90,
        status="OPEN",
        mitre_techniques=["T1078"],
        detection_ids=[str(d.id) for d in detections],
        affected_assets=["web-proxy-1"],
        affected_users=["victim_user"],
        source_ips=["203.0.113.88"],
    )
    db_session.add(incident)
    await db_session.flush()

    investigation = await run_investigation(
        db=db_session,
        tenant_id=tenant.id,
        incident_id=incident.id,
        force_refresh=True,
    )

    # Check H2 (Compromised Account)
    h2 = next((h for h in investigation.hypotheses if h.hypothesis_id == "H2"), None)
    assert h2 is not None
    assert h2.status in ("CONFIRMED", "LIKELY")
    assert h2.confidence >= 0.70
    assert str(succ_evt.id) in h2.evidence_ids or len(h2.evidence_ids) > 0


@pytest.mark.asyncio
async def test_scenario_c_normal_administrative_login(
    db_session: AsyncSession,
):
    """
    Scenario C: Normal single successful login.
    Expected: Possible legitimate activity (H5=LIKELY, H8=LIKELY).
    No automatic malicious conclusion.
    """
    tenant = Tenant(name="Investigate Tenant C")
    db_session.add(tenant)
    await db_session.flush()

    login_evt = SecurityEvent(
        tenant_id=tenant.id,
        source="sshd",
        event_type="authentication_success",
        severity="LOW",
        source_ip="10.0.0.15",
        username="sysadmin",
        hostname="backup-srv",
        timestamp=datetime.now(UTC),
        raw_event={"auth": {"result": "success"}},
        normalized_event={"event": {"type": "authentication_success"}, "source": {"ip": "10.0.0.15"}},
    )
    db_session.add(login_evt)
    await db_session.flush()

    incident = Incident(
        tenant_id=tenant.id,
        title="Admin Login: sysadmin",
        description="Routine administrative login.",
        severity="LOW",
        risk_score=20,
        confidence=0.85,
        status="OPEN",
        mitre_techniques=["T1078"],
        detection_ids=[],
        affected_assets=["backup-srv"],
        affected_users=["sysadmin"],
        source_ips=["10.0.0.15"],
    )
    db_session.add(incident)
    await db_session.flush()

    investigation = await run_investigation(
        db=db_session,
        tenant_id=tenant.id,
        incident_id=incident.id,
        force_refresh=True,
    )

    h5 = next((h for h in investigation.hypotheses if h.hypothesis_id == "H5"), None)
    assert h5 is not None
    assert h5.status in ("LIKELY", "CONFIRMED")

    # Brute force H4 should be UNKNOWN or DISPROVED
    h4 = next((h for h in investigation.hypotheses if h.hypothesis_id == "H4"), None)
    assert h4 is not None
    assert h4.status in ("UNKNOWN", "DISPROVED")


@pytest.mark.asyncio
async def test_scenario_d_insufficient_evidence_unknown_handling(
    db_session: AsyncSession,
):
    """
    Scenario D: Incident with no linked events.
    Expected: Hypotheses assign UNKNOWN. Never guess.
    """
    tenant = Tenant(name="Investigate Tenant D")
    db_session.add(tenant)
    await db_session.flush()

    incident = Incident(
        tenant_id=tenant.id,
        title="Sparse Telemetry Incident",
        description="Alert triggered without linked raw events.",
        severity="MEDIUM",
        risk_score=50,
        confidence=0.40,
        status="OPEN",
        mitre_techniques=[],
        detection_ids=[],
        affected_assets=[],
        affected_users=[],
        source_ips=[],
    )
    db_session.add(incident)
    await db_session.flush()

    investigation = await run_investigation(
        db=db_session,
        tenant_id=tenant.id,
        incident_id=incident.id,
        force_refresh=True,
    )

    # Hypotheses should be UNKNOWN when no evidence exists
    for hyp in investigation.hypotheses:
        assert hyp.status in ("UNKNOWN", "DISPROVED")
        assert len(hyp.evidence_ids) == 0

    assert "No security event evidence" in str(investigation.unknowns) or len(investigation.unknowns) > 0


@pytest.mark.asyncio
async def test_scenario_m_deterministic_investigation_offline_resilience(
    db_session: AsyncSession,
):
    """
    Scenario M: LLM unavailable / offline mode.
    Expected: Deterministic investigation remains fully functional with evidence grounding.
    """
    tenant = Tenant(name="Offline Tenant")
    db_session.add(tenant)
    await db_session.flush()

    incident = Incident(
        tenant_id=tenant.id,
        title="Offline Mode Test",
        description="Investigation runs without external LLM API.",
        severity="HIGH",
        risk_score=70,
        confidence=0.85,
        status="OPEN",
        mitre_techniques=["T1110.001"],
        detection_ids=[],
        affected_assets=["node-1"],
        affected_users=["user1"],
        source_ips=["198.51.100.99"],
    )
    db_session.add(incident)
    await db_session.flush()

    investigation = await run_investigation(
        db=db_session,
        tenant_id=tenant.id,
        incident_id=incident.id,
        force_refresh=True,
    )
    assert investigation.status == "COMPLETED"
    assert len(investigation.hypotheses) == 8
