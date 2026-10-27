from datetime import UTC, datetime

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.correlation.correlator import Correlator
from app.detection.engine import DetectionEngine
from app.detection.rule_loader import sync_rules_to_db
from app.models.event import SecurityEvent
from app.models.tenant import Tenant


@pytest.mark.asyncio
async def test_lsass_memory_access_attempt_triggers_critical_threat_rule(db_session: AsyncSession):
    """
    Verifies that an LSASS_MEMORY_ACCESS_ATTEMPT event produces a DetectionResult
    under AEGIS-SIG-CRITICAL-THREAT and correlates into an Incident.
    """
    tenant = Tenant(name="LSASS Threat Org")
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)

    await sync_rules_to_db(db_session)

    attacker_ip = "10.0.4.18"
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

    engine = DetectionEngine()
    detections = await engine.evaluate_events(db=db_session, tenant_id=tenant.id, events=[evt])

    matched = [d for d in detections if d.rule_id == "AEGIS-SIG-CRITICAL-THREAT"]
    assert len(matched) == 1, "LSASS_MEMORY_ACCESS_ATTEMPT must trigger AEGIS-SIG-CRITICAL-THREAT"
    detection = matched[0]
    assert detection.tenant_id == tenant.id
    assert detection.severity in {"CRITICAL", "HIGH"}
    assert str(evt.id) in detection.event_ids

    # Verify downstream Incident creation pipeline
    correlator = Correlator()
    incidents = await correlator.correlate_detections(db=db_session, tenant_id=tenant.id, detections=detections)
    assert len(incidents) >= 1, "Critical threat detection must correlate into an incident"
    inc = incidents[0]
    assert inc.tenant_id == tenant.id
    assert inc.status == "OPEN"
    assert attacker_ip in (inc.source_ips or [])


@pytest.mark.asyncio
async def test_mimikatz_execution_triggers_critical_threat_rule(db_session: AsyncSession):
    """
    Verifies that a MIMIKATZ_EXECUTION event produces a DetectionResult
    under AEGIS-SIG-CRITICAL-THREAT and correlates into an Incident.
    """
    tenant = Tenant(name="Mimikatz Threat Org")
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)

    await sync_rules_to_db(db_session)

    attacker_ip = "192.168.10.45"
    evt = SecurityEvent(
        tenant_id=tenant.id,
        timestamp=datetime.now(UTC),
        source="sentinelone-agent",
        event_type="MIMIKATZ_EXECUTION",
        severity="HIGH",
        source_ip=attacker_ip,
        username="compromised_admin",
        hostname="finance-ws-04",
        raw_event={"command": "sekurlsa::logonpasswords"},
        normalized_event={
            "event": {"type": "mimikatz_execution"},
            "source": {"ip": attacker_ip},
            "user": {"name": "compromised_admin"},
        },
    )
    db_session.add(evt)
    await db_session.commit()

    engine = DetectionEngine()
    detections = await engine.evaluate_events(db=db_session, tenant_id=tenant.id, events=[evt])

    matched = [d for d in detections if d.rule_id == "AEGIS-SIG-CRITICAL-THREAT"]
    assert len(matched) == 1, "MIMIKATZ_EXECUTION must trigger AEGIS-SIG-CRITICAL-THREAT"
    assert str(evt.id) in matched[0].event_ids

    correlator = Correlator()
    incidents = await correlator.correlate_detections(db=db_session, tenant_id=tenant.id, detections=detections)
    assert len(incidents) >= 1, "Mimikatz detection must correlate into an incident"
    assert incidents[0].status == "OPEN"


@pytest.mark.asyncio
async def test_critical_severity_event_triggers_critical_threat_rule(db_session: AsyncSession):
    """
    Verifies that any security telemetry with severity=CRITICAL produces a DetectionResult
    under AEGIS-SIG-CRITICAL-THREAT even if the specific event_type is generic or novel.
    """
    tenant = Tenant(name="Critical Severity Org")
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)

    await sync_rules_to_db(db_session)

    attacker_ip = "172.16.5.99"
    evt = SecurityEvent(
        tenant_id=tenant.id,
        timestamp=datetime.now(UTC),
        source="paloalto-cortex",
        event_type="SUSPICIOUS_KERNEL_MODULE_LOAD",
        severity="CRITICAL",
        source_ip=attacker_ip,
        username="root",
        hostname="core-router-01",
        raw_event={"module": "rootkit_mod.ko"},
        normalized_event={
            "event": {"type": "suspicious_kernel_module_load"},
            "source": {"ip": attacker_ip},
        },
    )
    db_session.add(evt)
    await db_session.commit()

    engine = DetectionEngine()
    detections = await engine.evaluate_events(db=db_session, tenant_id=tenant.id, events=[evt])

    matched = [d for d in detections if d.rule_id == "AEGIS-SIG-CRITICAL-THREAT"]
    assert len(matched) == 1, "CRITICAL severity event must trigger AEGIS-SIG-CRITICAL-THREAT"
    assert str(evt.id) in matched[0].event_ids

    correlator = Correlator()
    incidents = await correlator.correlate_detections(db=db_session, tenant_id=tenant.id, detections=detections)
    assert len(incidents) >= 1, "Critical severity detection must correlate into an incident"


@pytest.mark.asyncio
async def test_unrelated_high_medium_informational_events_do_not_trigger(db_session: AsyncSession):
    """
    Verifies that unrelated HIGH, MEDIUM, and INFO events do NOT match
    AEGIS-SIG-CRITICAL-THREAT unless they meet explicit threat criteria.
    """
    tenant = Tenant(name="Non Critical Org")
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)

    await sync_rules_to_db(db_session)

    # 1. High severity but benign event type
    evt_high_benign = SecurityEvent(
        tenant_id=tenant.id,
        timestamp=datetime.now(UTC),
        source="firewall",
        event_type="NETWORK_CONNECTION",
        severity="HIGH",
        source_ip="192.168.1.100",
        username="normal_user",
        hostname="pc-1",
        raw_event={"bytes": 1024},
        normalized_event={"event": {"type": "network_connection"}},
    )

    # 2. Medium severity single auth failure (below brute-force threshold)
    evt_med_auth = SecurityEvent(
        tenant_id=tenant.id,
        timestamp=datetime.now(UTC),
        source="sshd",
        event_type="AUTH_FAILURE",
        severity="MEDIUM",
        source_ip="192.168.1.101",
        username="normal_user",
        hostname="pc-2",
        raw_event={"error": "wrong pwd"},
        normalized_event={"event": {"type": "auth_failure"}},
    )

    # 3. Informational process creation
    evt_info_proc = SecurityEvent(
        tenant_id=tenant.id,
        timestamp=datetime.now(UTC),
        source="auditd",
        event_type="PROCESS_CREATION",
        severity="INFO",
        source_ip="192.168.1.102",
        username="normal_user",
        hostname="pc-3",
        raw_event={"exe": "bash"},
        normalized_event={"event": {"type": "process_creation"}},
    )

    db_session.add_all([evt_high_benign, evt_med_auth, evt_info_proc])
    await db_session.commit()

    engine = DetectionEngine()
    detections = await engine.evaluate_events(
        db=db_session,
        tenant_id=tenant.id,
        events=[evt_high_benign, evt_med_auth, evt_info_proc],
    )

    matched = [d for d in detections if d.rule_id == "AEGIS-SIG-CRITICAL-THREAT"]
    assert len(matched) == 0, (
        f"Unrelated events must NOT match AEGIS-SIG-CRITICAL-THREAT, but found: {[d.rule_id for d in matched]}"
    )


@pytest.mark.asyncio
async def test_critical_threat_tenant_isolation(db_session: AsyncSession):
    """
    Verifies strict tenant isolation: an LSASS threat in Tenant A must never
    produce detections or incidents visible to Tenant B.
    """
    tenant_a = Tenant(name="Critical Org A")
    tenant_b = Tenant(name="Critical Org B")
    db_session.add_all([tenant_a, tenant_b])
    await db_session.commit()
    await db_session.refresh(tenant_a)
    await db_session.refresh(tenant_b)

    await sync_rules_to_db(db_session)

    evt_a = SecurityEvent(
        tenant_id=tenant_a.id,
        timestamp=datetime.now(UTC),
        source="edr",
        event_type="LSASS_MEMORY_ACCESS_ATTEMPT",
        severity="HIGH",
        source_ip="10.0.1.5",
        username="SYSTEM",
        hostname="dc-tenant-a",
        raw_event={"alert": "LSASS memory dump"},
        normalized_event={"event": {"type": "lsass_memory_access_attempt"}},
    )
    db_session.add(evt_a)
    await db_session.commit()

    engine = DetectionEngine()
    # Evaluate for Tenant A
    detections_a = await engine.evaluate_events(db=db_session, tenant_id=tenant_a.id, events=[evt_a])
    assert len(detections_a) == 1
    assert detections_a[0].tenant_id == tenant_a.id

    # Cross-tenant evaluation check: passing evt_a to Tenant B must raise ValueError
    with pytest.raises(ValueError, match="Cross-tenant evaluation detected"):
        await engine.evaluate_events(db=db_session, tenant_id=tenant_b.id, events=[evt_a])
