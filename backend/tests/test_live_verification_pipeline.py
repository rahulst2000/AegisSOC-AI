import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.correlation.correlator import Correlator
from app.detection.engine import DetectionEngine
from app.detection.evaluator import matches_canonical_event_type
from app.detection.rule_loader import sync_rules_to_db
from app.models.event import SecurityEvent
from app.models.incident import Incident
from app.models.tenant import Tenant
from app.schemas.event import SecurityEventCreate
from app.schemas.incident import IncidentRead
from app.services.event_service import create_security_event
from app.workers.correlation_worker import CorrelationWorker
from app.workers.detection_worker import DetectionWorker
from app.workers.queue import (
    _in_memory_detection_queue,
    _in_memory_event_queue,
    dequeue_detection,
    dequeue_event,
    enqueue_detection_for_correlation,
    enqueue_event_for_detection,
)


@pytest.mark.asyncio
async def test_canonical_auth_normalization():
    """Verifies that all auth failure variations canonically map to AUTH_FAILURE."""
    assert matches_canonical_event_type("SSH_LOGIN_FAILURE", "AUTH_FAILURE") is True
    assert matches_canonical_event_type("ssh_login_failure", "AUTH_FAILURE") is True
    assert matches_canonical_event_type("SSH_AUTH_FAILURE", "AUTH_FAILURE") is True
    assert matches_canonical_event_type("LOGIN_FAILED", "AUTH_FAILURE") is True
    assert matches_canonical_event_type("SSH_LOGIN_SUCCESS", "AUTH_SUCCESS") is True
    assert matches_canonical_event_type("PORT_SCAN", "AUTH_FAILURE") is False


@pytest.mark.asyncio
async def test_queue_resilient_fallback_mode():
    """Verifies in-memory fallback queue for zero-loss operation when Redis is unavailable."""
    # Drain any lingering events from preceding test cases
    while await dequeue_event():
        pass
    while await dequeue_detection():
        pass

    event_id = str(uuid.uuid4())
    tenant_id = str(uuid.uuid4())

    await enqueue_event_for_detection(event_id, tenant_id)
    dequeued = await dequeue_event()
    assert dequeued is not None
    assert dequeued["event_id"] == event_id
    assert dequeued["tenant_id"] == tenant_id

    det_id = str(uuid.uuid4())
    await enqueue_detection_for_correlation(det_id, tenant_id)
    dequeued_det = await dequeue_detection()
    assert dequeued_det is not None
    assert dequeued_det["detection_id"] == det_id


@pytest.mark.asyncio
async def test_incident_model_schema_attributes(db_session: AsyncSession):
    """Verifies that the Incident model has all Phase 2-5 schema attributes and serializes properly."""
    tenant = Tenant(name=f"Incident Schema Tenant {uuid.uuid4().hex[:6]}")
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)

    now = datetime.now(UTC)
    incident = Incident(
        tenant_id=tenant.id,
        title="Schema Attributes Verification Incident",
        description="Verifying all extended columns are queryable and serializable.",
        severity="HIGH",
        risk_score=75.0,
        confidence=0.9,
        status="OPEN",
        mitre_techniques=["T1003.001", "T1059.001"],
        detection_ids=["AEGIS-SIG-CRITICAL-THREAT-01"],
        affected_assets=["bastion-01", "dc-01"],
        affected_users=["admin", "root"],
        source_ips=["198.51.100.42"],
        first_seen=now,
        last_seen=now,
    )
    db_session.add(incident)
    await db_session.commit()
    await db_session.refresh(incident)

    stmt = select(Incident).where(Incident.id == incident.id)
    res = await db_session.execute(stmt)
    fetched = res.scalars().first()

    assert fetched is not None
    assert fetched.mitre_techniques == ["T1003.001", "T1059.001"]
    assert fetched.affected_assets == ["bastion-01", "dc-01"]
    assert fetched.source_ips == ["198.51.100.42"]

    # Verify Pydantic schema serialization
    read_schema = IncidentRead.model_validate(fetched)
    assert read_schema.id == incident.id
    assert read_schema.title == incident.title


@pytest.mark.asyncio
async def test_end_to_end_telemetry_pipeline_to_incident(db_session: AsyncSession):
    """
    Traces and verifies the complete telemetry pipeline:
    SecurityEvent -> DetectionEngine -> DetectionResult -> Correlator -> Incident.
    Verifies that critical threats and repeated failures automatically elevate to Incidents.
    """
    tenant = Tenant(name=f"E2E Pipeline Org {uuid.uuid4().hex[:6]}")
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)

    # 1. Sync rules
    synced_rules = await sync_rules_to_db(db_session)
    assert len(synced_rules) >= 7

    # 2. Ingest SecurityEvent for critical threat
    attacker_ip = "198.51.100.77"
    evt = SecurityEvent(
        tenant_id=tenant.id,
        timestamp=datetime.now(UTC),
        source="crowdstrike-edr",
        event_type="LSASS_MEMORY_ACCESS_ATTEMPT",
        severity="HIGH",
        source_ip=attacker_ip,
        username="SYSTEM",
        hostname="domain-controller-01",
        raw_event={"process": "lsass.exe", "action": "OpenProcessMemoryDump"},
        normalized_event={
            "event": {"type": "lsass_memory_access_attempt"},
            "source": {"ip": attacker_ip},
            "user": {"name": "SYSTEM"},
        },
    )
    db_session.add(evt)
    await db_session.commit()
    await db_session.refresh(evt)

    # 3. DetectionEngine evaluation
    engine = DetectionEngine()
    detections = await engine.evaluate_events(db=db_session, tenant_id=tenant.id, events=[evt])
    assert len(detections) >= 1
    det = detections[0]
    assert det.rule_id == "AEGIS-SIG-CRITICAL-THREAT"

    # 4. Correlator produces Incident
    correlator = Correlator()
    incidents = await correlator.correlate_detections(db=db_session, tenant_id=tenant.id, detections=detections)
    assert len(incidents) >= 1

    inc = incidents[0]
    assert inc.tenant_id == tenant.id
    assert inc.status == "OPEN"
    assert attacker_ip in (inc.source_ips or [])
    assert inc.risk_score >= 70.0


@pytest.mark.asyncio
async def test_worker_zero_loss_reconciliation_after_restart(db_session: AsyncSession):
    """
    Regression test for production container restart / queue fallback gap:
    Proves that when events are ingested and in-memory queue is wiped (simulating
    container reboot in non-Redis environment), DetectionWorker and CorrelationWorker
    reconcile existing database telemetry and produce the Incident without data loss.
    """
    tenant = Tenant(name=f"Reconciliation Org {uuid.uuid4().hex[:6]}")
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)

    await sync_rules_to_db(db_session)

    # 1. Ingest LSASS critical threat event via event_service
    event_in = SecurityEventCreate(
        source="CrowdStrike-EDR",
        event_type="LSASS_MEMORY_ACCESS_ATTEMPT",
        severity="CRITICAL",
        source_ip="10.0.4.18",
        username="svc_backup",
        hostname="dc-primary.corp",
        raw_event={
            "ProcessName": "mimikatz.exe",
            "TargetProcess": "lsass.exe",
            "GrantedAccess": "0x1010",
        },
    )
    evt = await create_security_event(db=db_session, tenant_id=tenant.id, event_in=event_in)
    assert evt.id is not None

    # 2. Simulate container restart: wipe in-memory queues completely
    _in_memory_event_queue.clear()
    _in_memory_detection_queue.clear()

    # 3. DetectionWorker runs against DB fallback
    dw = DetectionWorker()
    detections = await dw.process_next_event(db_session, tenant_id=tenant.id)
    assert len(detections) >= 1, "DetectionWorker must reconcile un-evaluated event from DB"
    matched_det = detections[0]
    assert matched_det.rule_id == "AEGIS-SIG-CRITICAL-THREAT"

    # 4. CorrelationWorker runs against queue or DB fallback
    cw = CorrelationWorker()
    incidents = await cw.process_next_detection(db_session, tenant_id=tenant.id)
    assert len(incidents) >= 1, "CorrelationWorker must correlate reconciled detection into Incident"

    # 5. Verify database persistence and schema
    stmt = select(Incident).where(Incident.tenant_id == tenant.id)
    res = await db_session.execute(stmt)
    all_incs = list(res.scalars().all())
    assert len(all_incs) == 1
    inc = all_incs[0]
    assert inc.severity == "CRITICAL"
    assert inc.status == "OPEN"
    assert "10.0.4.18" in (inc.source_ips or [])
    assert "svc_backup" in (inc.affected_users or [])
    assert "dc-primary.corp" in (inc.affected_assets or [])
    assert any("T1003" in t for t in (inc.mitre_techniques or []))


@pytest.mark.asyncio
async def test_un_correlated_detection_dedup_trap_recovery(db_session: AsyncSession):
    """
    Regression test for deduplication trap:
    Proves that if DetectionResult was persisted but never correlated into an Incident,
    DetectionEngine does not drop it, and CorrelationWorker successfully correlates it.
    """
    tenant = Tenant(name=f"Dedup Trap Org {uuid.uuid4().hex[:6]}")
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)

    await sync_rules_to_db(db_session)

    # 1. Ingest event
    event_in = SecurityEventCreate(
        source="CrowdStrike-EDR",
        event_type="LSASS_MEMORY_ACCESS_ATTEMPT",
        severity="CRITICAL",
        source_ip="10.0.4.18",
        username="svc_backup",
        hostname="dc-primary.corp",
        raw_event={"ProcessName": "mimikatz.exe", "TargetProcess": "lsass.exe"},
    )
    evt = await create_security_event(db=db_session, tenant_id=tenant.id, event_in=event_in)

    # 2. Process event with DetectionWorker -> creates DetectionResult in DB
    dw = DetectionWorker()
    dets = await dw.process_next_event(db_session, tenant_id=tenant.id)
    assert len(dets) >= 1

    # 3. Simulate failure before correlation: clear detection queue
    _in_memory_detection_queue.clear()

    # 4. CorrelationWorker detects un-correlated DetectionResult in DB and correlates it
    cw = CorrelationWorker()
    incs = await cw.process_next_detection(db_session, tenant_id=tenant.id)
    assert len(incs) >= 1, "CorrelationWorker must recover un-correlated detection from DB"

    stmt = select(Incident).where(Incident.tenant_id == tenant.id)
    res = await db_session.execute(stmt)
    all_incs = list(res.scalars().all())
    assert len(all_incs) == 1
    assert all_incs[0].severity == "CRITICAL"
