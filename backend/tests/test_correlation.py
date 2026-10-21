import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.correlation.correlator import Correlator
from app.detection.engine import DetectionEngine
from app.detection.rule_loader import sync_rules_to_db
from app.models.event import SecurityEvent
from app.models.incident import Incident
from app.models.tenant import Tenant


@pytest.mark.asyncio
async def test_scenario_e_cross_tenant_isolation_in_correlation(db_session: AsyncSession):
    """
    Scenario E: Same attack pattern in Tenant A and Tenant B.
    Expected: Two completely independent tenant-scoped incidents.
    Never correlate events/detections across tenants!
    """
    # 1. Create two distinct tenants
    tenant_a = Tenant(name="Tenant Alpha Security")
    tenant_b = Tenant(name="Tenant Bravo Defense")
    db_session.add_all([tenant_a, tenant_b])
    await db_session.commit()
    await db_session.refresh(tenant_a)
    await db_session.refresh(tenant_b)

    await sync_rules_to_db(db_session)

    attacker_ip = "185.220.101.5"
    base_time = datetime.now(UTC)

    # 2. Ingest 10 failed logins for Tenant A
    events_a: list[SecurityEvent] = []
    for i in range(10):
        evt = SecurityEvent(
            tenant_id=tenant_a.id,
            timestamp=base_time + timedelta(seconds=i * 2),
            source="ssh",
            event_type="AUTH_FAILURE",
            severity="LOW",
            source_ip=attacker_ip,
            username="root",
            hostname="shared-bastion",
            raw_event={"msg": "Failed auth", "ip": attacker_ip},
            normalized_event={"event": {"type": "auth_failure"}, "source": {"ip": attacker_ip}},
        )
        db_session.add(evt)
        events_a.append(evt)

    # 3. Ingest identical 10 failed logins for Tenant B
    events_b: list[SecurityEvent] = []
    for i in range(10):
        evt = SecurityEvent(
            tenant_id=tenant_b.id,
            timestamp=base_time + timedelta(seconds=i * 2),
            source="ssh",
            event_type="AUTH_FAILURE",
            severity="LOW",
            source_ip=attacker_ip,
            username="root",
            hostname="shared-bastion",
            raw_event={"msg": "Failed auth", "ip": attacker_ip},
            normalized_event={"event": {"type": "auth_failure"}, "source": {"ip": attacker_ip}},
        )
        db_session.add(evt)
        events_b.append(evt)

    await db_session.commit()

    # 4. Evaluate detections independently
    engine = DetectionEngine()
    dets_a = await engine.evaluate_events(db=db_session, tenant_id=tenant_a.id, events=events_a)
    dets_b = await engine.evaluate_events(db=db_session, tenant_id=tenant_b.id, events=events_b)

    assert len(dets_a) >= 1
    assert len(dets_b) >= 1
    assert all(d.tenant_id == tenant_a.id for d in dets_a)
    assert all(d.tenant_id == tenant_b.id for d in dets_b)

    # 5. Correlate independently
    correlator = Correlator()
    incidents_a = await correlator.correlate_detections(db=db_session, tenant_id=tenant_a.id, detections=dets_a)
    incidents_b = await correlator.correlate_detections(db=db_session, tenant_id=tenant_b.id, detections=dets_b)

    assert len(incidents_a) == 1
    assert len(incidents_b) == 1
    inc_a = incidents_a[0]
    inc_b = incidents_b[0]

    # Critical security assertions: Incidents must remain completely distinct
    assert inc_a.id != inc_b.id
    assert inc_a.tenant_id == tenant_a.id
    assert inc_b.tenant_id == tenant_b.id
    assert inc_a.tenant_id != inc_b.tenant_id


@pytest.mark.asyncio
async def test_scenario_f_duplicate_event_processing_idempotence(db_session: AsyncSession):
    """
    Scenario F: Same event batch processed twice.
    Expected: No duplicate incident created; deduplication hash preserves idempotency.
    """
    tenant = Tenant(name="Idempotence Org")
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)

    await sync_rules_to_db(db_session)

    attacker_ip = "198.51.100.99"
    events: list[SecurityEvent] = []
    base_time = datetime.now(UTC)

    for i in range(10):
        evt = SecurityEvent(
            tenant_id=tenant.id,
            timestamp=base_time + timedelta(seconds=i * 2),
            source="ssh",
            event_type="AUTH_FAILURE",
            severity="LOW",
            source_ip=attacker_ip,
            username="admin",
            hostname="gateway-1",
            raw_event={"msg": "Failed auth", "ip": attacker_ip},
            normalized_event={"event": {"type": "auth_failure"}, "source": {"ip": attacker_ip}},
        )
        db_session.add(evt)
        events.append(evt)

    await db_session.commit()

    engine = DetectionEngine()
    correlator = Correlator()

    # Pass 1
    dets_pass1 = await engine.evaluate_events(db=db_session, tenant_id=tenant.id, events=events)
    assert len(dets_pass1) >= 1
    incidents_pass1 = await correlator.correlate_detections(db=db_session, tenant_id=tenant.id, detections=dets_pass1)
    assert len(incidents_pass1) == 1

    # Pass 2: Re-evaluating the identical events
    dets_pass2 = await engine.evaluate_events(db=db_session, tenant_id=tenant.id, events=events)
    # DetectionEngine must detect duplicate hash and not spawn new detection results
    assert len(dets_pass2) == 0

    # Total incidents for this tenant must still be exactly 1
    stmt = select(Incident).where(Incident.tenant_id == tenant.id)
    res = await db_session.execute(stmt)
    all_incidents = list(res.scalars().all())
    assert len(all_incidents) == 1


@pytest.mark.asyncio
async def test_scenario_g_events_outside_correlation_window(db_session: AsyncSession):
    """
    Scenario G: Events separated beyond correlation window.
    Expected: Detections occurring hours apart are not merged into a single temporal incident.
    """
    tenant = Tenant(name="Window Test Org")
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)

    await sync_rules_to_db(db_session)

    attacker_ip = "203.0.113.50"
    base_time = datetime.now(UTC) - timedelta(hours=5)
    later_time = datetime.now(UTC)

    # Batch 1: 10 events 5 hours ago
    events_early: list[SecurityEvent] = []
    for i in range(10):
        evt = SecurityEvent(
            tenant_id=tenant.id,
            timestamp=base_time + timedelta(seconds=i * 2),
            source="ssh",
            event_type="AUTH_FAILURE",
            severity="LOW",
            source_ip=attacker_ip,
            username="root",
            hostname="host-a",
            raw_event={"msg": "Failed auth", "ip": attacker_ip},
            normalized_event={"event": {"type": "auth_failure"}, "source": {"ip": attacker_ip}},
        )
        db_session.add(evt)
        events_early.append(evt)

    # Batch 2: 10 events now (5 hours later)
    events_late: list[SecurityEvent] = []
    for i in range(10):
        evt = SecurityEvent(
            tenant_id=tenant.id,
            timestamp=later_time + timedelta(seconds=i * 2),
            source="ssh",
            event_type="AUTH_FAILURE",
            severity="LOW",
            source_ip=attacker_ip,
            username="root",
            hostname="host-a",
            raw_event={"msg": "Failed auth", "ip": attacker_ip},
            normalized_event={"event": {"type": "auth_failure"}, "source": {"ip": attacker_ip}},
        )
        db_session.add(evt)
        events_late.append(evt)

    await db_session.commit()

    engine = DetectionEngine()
    correlator = Correlator()

    dets_early = await engine.evaluate_events(db=db_session, tenant_id=tenant.id, events=events_early)
    dets_late = await engine.evaluate_events(db=db_session, tenant_id=tenant.id, events=events_late)

    # Correlate all detections together
    all_dets = dets_early + dets_late
    incidents = await correlator.correlate_detections(db=db_session, tenant_id=tenant.id, detections=all_dets)

    # Because detections are 5 hours apart and window is 15 minutes, they must be partitioned into 2 distinct incidents
    assert len(incidents) == 2
    assert incidents[0].id != incidents[1].id


@pytest.mark.asyncio
async def test_incident_timeline_api(client: AsyncClient, db_session: AsyncSession):
    """
    Verifies GET /api/v1/incidents/{incident_id}/timeline returns chronological forensic timeline.
    """
    # 1. Register security analyst
    reg_res = await client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Timeline Org",
            "email": "analyst@timelineorg.com",
            "password": "Password123!",
            "role": "SOC_L2",
        },
    )
    assert reg_res.status_code == 201
    token = reg_res.json()["access_token"]
    tenant_id = uuid.UUID(reg_res.json()["user"]["tenant_id"])
    headers = {"Authorization": f"Bearer {token}"}

    await sync_rules_to_db(db_session)

    # 2. Ingest 10 events, run engine and correlator
    attacker_ip = "192.0.2.77"
    base_time = datetime.now(UTC)
    events: list[SecurityEvent] = []

    for i in range(10):
        evt = SecurityEvent(
            tenant_id=tenant_id,
            timestamp=base_time + timedelta(seconds=i * 2),
            source="ssh",
            event_type="AUTH_FAILURE",
            severity="LOW",
            source_ip=attacker_ip,
            username="root",
            hostname="srv-01",
            raw_event={"msg": "Failed auth", "ip": attacker_ip},
            normalized_event={"event": {"type": "auth_failure"}, "source": {"ip": attacker_ip}},
        )
        db_session.add(evt)
        events.append(evt)

    await db_session.commit()

    engine = DetectionEngine()
    correlator = Correlator()
    dets = await engine.evaluate_events(db=db_session, tenant_id=tenant_id, events=events)
    incidents = await correlator.correlate_detections(db=db_session, tenant_id=tenant_id, detections=dets)
    assert len(incidents) == 1
    incident = incidents[0]

    # 3. Query timeline API
    inc_id = str(incident.id)
    timeline_res = await client.get(f"/api/v1/incidents/{inc_id}/timeline", headers=headers)
    assert timeline_res.status_code == 200
    timeline = timeline_res.json()
    assert isinstance(timeline, list)
    assert len(timeline) >= 2

    # Check item types present in timeline
    item_types = {item["item_type"] for item in timeline}
    assert "DETECTION" in item_types or "SECURITY_EVENT" in item_types
