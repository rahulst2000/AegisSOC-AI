import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.correlation.correlator import Correlator
from app.detection.engine import DetectionEngine
from app.detection.models import DetectionRule
from app.detection.registry import global_rule_registry
from app.detection.rule_loader import sync_rules_to_db
from app.models.event import SecurityEvent
from app.models.tenant import Tenant


@pytest.mark.asyncio
async def test_ssh_auth_failure_matches_canonical_auth_failure_rule(db_session: AsyncSession):
    """Verifies SSH_AUTH_FAILURE can match rules expecting canonical AUTH_FAILURE."""
    tenant = Tenant(name="Canonical Auth Org")
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)

    # Register a rule that strictly expects canonical AUTH_FAILURE
    strict_rule = DetectionRule(
        rule_id=f"TEST-STRICT-AUTH-FAIL-{uuid.uuid4().hex[:6].upper()}",
        tenant_id=tenant.id,
        name="Strict Auth Failure Rule",
        description="Matches canonical auth failure",
        enabled=True,
        severity="HIGH",
        confidence=0.9,
        event_types=["AUTH_FAILURE"],
        conditions={
            "selections": {
                "selection": {
                    "event_type": "AUTH_FAILURE",
                }
            },
            "condition": "selection",
        },
    )
    db_session.add(strict_rule)
    await db_session.commit()
    global_rule_registry.register(strict_rule)

    evt = SecurityEvent(
        tenant_id=tenant.id,
        timestamp=datetime.now(UTC),
        source="ssh",
        event_type="SSH_AUTH_FAILURE",
        severity="HIGH",
        source_ip="192.168.1.50",
        username="admin",
        hostname="server-01",
        raw_event={"msg": "SSH authentication failed"},
        normalized_event={"event": {"type": "ssh_auth_failure"}},
    )
    db_session.add(evt)
    await db_session.commit()

    engine = DetectionEngine()
    detections = await engine.evaluate_events(db=db_session, tenant_id=tenant.id, events=[evt])

    matched = [d for d in detections if d.rule_id == strict_rule.rule_id]
    assert len(matched) == 1, "SSH_AUTH_FAILURE must match rule expecting canonical AUTH_FAILURE"


@pytest.mark.asyncio
async def test_five_ssh_auth_failures_satisfies_password_spraying(db_session: AsyncSession):
    """
    Verifies that five SSH_AUTH_FAILURE events from the same IP across five distinct
    usernames satisfies the password-spraying rule (>4 distinct usernames) and creates an incident.
    """
    tenant = Tenant(name="Spray Test Org")
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)

    await sync_rules_to_db(db_session)

    attacker_ip = "10.10.10.50"
    target_host = "web-server-01"
    usernames = ["admin", "user01", "user02", "user03", "user04"]
    base_time = datetime.now(UTC)
    events: list[SecurityEvent] = []

    for idx, user in enumerate(usernames):
        evt = SecurityEvent(
            tenant_id=tenant.id,
            timestamp=base_time + timedelta(seconds=idx * 2),
            source="CrowdStrike-EDR",
            event_type="SSH_AUTH_FAILURE",
            severity="HIGH",
            source_ip=attacker_ip,
            username=user,
            hostname=target_host,
            raw_event={"failure_reason": "bad_password", "user": user},
            normalized_event={
                "event": {"type": "ssh_auth_failure"},
                "source": {"ip": attacker_ip},
                "user": {"name": user},
            },
        )
        db_session.add(evt)
        events.append(evt)

    await db_session.commit()

    engine = DetectionEngine()
    detections = await engine.evaluate_events(db=db_session, tenant_id=tenant.id, events=events)

    spray_detection = next((d for d in detections if "SPRAYING" in d.rule_id), None)
    assert spray_detection is not None, "5 SSH_AUTH_FAILURE with distinct usernames must trigger password spraying"
    assert len(spray_detection.event_ids) >= 5

    correlator = Correlator()
    incidents = await correlator.correlate_detections(db=db_session, tenant_id=tenant.id, detections=detections)

    assert len(incidents) >= 1, "Password spraying detections must correlate into an incident"
    inc = incidents[0]
    assert inc.tenant_id == tenant.id
    assert inc.status == "OPEN"
    assert attacker_ip in (inc.source_ips or [])


@pytest.mark.asyncio
async def test_ten_ssh_auth_failures_satisfies_ssh_bruteforce(db_session: AsyncSession):
    """
    Verifies that ten SSH_AUTH_FAILURE events from the same IP satisfies the
    SSH brute-force threshold (>9) and creates an incident.
    """
    tenant = Tenant(name="BruteForce Test Org")
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)

    await sync_rules_to_db(db_session)

    attacker_ip = "10.10.10.50"
    base_time = datetime.now(UTC)
    events: list[SecurityEvent] = []

    for i in range(10):
        evt = SecurityEvent(
            tenant_id=tenant.id,
            timestamp=base_time + timedelta(seconds=i * 3),
            source="ssh",
            event_type="SSH_AUTH_FAILURE",
            severity="HIGH",
            source_ip=attacker_ip,
            username="root",
            hostname="web-server-01",
            raw_event={"ip": attacker_ip, "attempt": i},
            normalized_event={"event": {"type": "ssh_auth_failure"}, "source": {"ip": attacker_ip}},
        )
        db_session.add(evt)
        events.append(evt)

    await db_session.commit()

    engine = DetectionEngine()
    detections = await engine.evaluate_events(db=db_session, tenant_id=tenant.id, events=events)

    bf_detection = next((d for d in detections if "BRUTEFORCE" in d.rule_id), None)
    assert bf_detection is not None, "10 SSH_AUTH_FAILURE events must satisfy SSH brute-force threshold (>9)"

    correlator = Correlator()
    incidents = await correlator.correlate_detections(db=db_session, tenant_id=tenant.id, detections=detections)

    assert len(incidents) >= 1, "Brute force detections must correlate into an incident"


@pytest.mark.asyncio
async def test_existing_canonical_auth_failure_remains_unchanged(db_session: AsyncSession):
    """Verifies existing AUTH_FAILURE events continue to match properly."""
    tenant = Tenant(name="Canonical Regression Org")
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)

    await sync_rules_to_db(db_session)

    attacker_ip = "192.168.100.99"
    base_time = datetime.now(UTC)
    events: list[SecurityEvent] = []

    for i in range(10):
        evt = SecurityEvent(
            tenant_id=tenant.id,
            timestamp=base_time + timedelta(seconds=i * 2),
            source="ssh",
            event_type="AUTH_FAILURE",
            severity="LOW",
            source_ip=attacker_ip,
            username="admin",
            hostname="bastion-01",
            raw_event={"msg": "Failed"},
            normalized_event={"event": {"type": "auth_failure"}},
        )
        db_session.add(evt)
        events.append(evt)

    await db_session.commit()

    engine = DetectionEngine()
    detections = await engine.evaluate_events(db=db_session, tenant_id=tenant.id, events=events)

    bf = next((d for d in detections if "BRUTEFORCE" in d.rule_id), None)
    assert bf is not None, "Canonical AUTH_FAILURE must continue to trigger brute-force"


@pytest.mark.asyncio
async def test_unrelated_event_types_not_matched(db_session: AsyncSession):
    """Verifies that unrelated event types do not accidentally match authentication rules."""
    tenant = Tenant(name="Unrelated Events Org")
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)

    await sync_rules_to_db(db_session)

    unrelated_types = [
        "PROCESS_CREATE",
        "LSASS_MEMORY_ACCESS_ATTEMPT",
        "DNS_QUERY",
        "FILE_WRITE",
        "NETWORK_CONNECT",
    ]
    base_time = datetime.now(UTC)
    events: list[SecurityEvent] = []

    for idx, et in enumerate(unrelated_types):
        evt = SecurityEvent(
            tenant_id=tenant.id,
            timestamp=base_time + timedelta(seconds=idx * 5),
            source="CrowdStrike-EDR",
            event_type=et,
            severity="HIGH",
            source_ip="10.0.0.1",
            username="system",
            hostname="host-01",
            raw_event={"event": et},
            normalized_event={"event": {"type": et.lower()}},
        )
        db_session.add(evt)
        events.append(evt)

    await db_session.commit()

    engine = DetectionEngine()
    detections = await engine.evaluate_events(db=db_session, tenant_id=tenant.id, events=events)

    # None of the authentication rules should match unrelated events
    auth_rule_ids = {
        "AEGIS-SIG-SSH-BRUTEFORCE",
        "AEGIS-SIG-PASSWORD-SPRAYING",
        "AEGIS-SIG-MULTI-FAIL-IP",
        "AEGIS-SIG-FAILURE-THEN-SUCCESS",
        "AEGIS-SIG-INVALID-USER",
        "AEGIS-SIG-PRIVILEGED-LOGIN",
    }
    matched_auth = [d for d in detections if d.rule_id in auth_rule_ids]
    assert len(matched_auth) == 0, "Unrelated events must not match authentication rules"
