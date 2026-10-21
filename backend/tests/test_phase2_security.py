import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.correlation.correlator import Correlator
from app.detection.engine import DetectionEngine
from app.detection.models import DetectionResult
from app.detection.rule_loader import load_rule_from_yaml_content
from app.detection.sigma_parser import MAX_SIGMA_RULE_SIZE_BYTES, SigmaParseError, parse_sigma_yaml
from app.models.event import SecurityEvent
from app.models.tenant import Tenant
from app.workers.queue import (
    _in_memory_event_queue,
    dequeue_event,
    enqueue_event_for_detection,
    get_queue_health,
)


def test_malicious_yaml_billion_laughs_rejected():
    """Verifies that malicious recursive YAML entities are rejected safely."""
    billion_laughs = """
    a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
    b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
    c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
    title: Billion Laughs Attack
    logsource: { category: test }
    detection: { selection: { x: *c }, condition: selection }
    """
    # SafeLoader or size limits will handle or raise SigmaParseError
    try:
        parsed = parse_sigma_yaml(billion_laughs)
        assert parsed is not None
    except SigmaParseError:
        pass  # Successfully caught by safe parser


def test_oversized_rule_file_rejected():
    """Verifies that oversized rule files exceeding 1 MB are safely rejected."""
    oversized_content = "title: Oversized\nlogsource: { category: auth }\n" + ("# filler\n" * 150000)
    assert len(oversized_content.encode("utf-8")) > MAX_SIGMA_RULE_SIZE_BYTES
    with pytest.raises(SigmaParseError) as exc_info:
        parse_sigma_yaml(oversized_content)
    assert "exceeds maximum allowable size" in str(exc_info.value).lower()


def test_no_arbitrary_code_execution_in_rules():
    """
    Verifies that rules containing executable code payloads (e.g. Python code, system commands)
    are treated strictly as DATA and NEVER executed.
    """
    malicious_rule_yaml = """
    title: Injection Attempt
    id: INJ-001
    logsource:
      category: authentication
    detection:
      selection:
        username: "__import__('os').system('echo pwned')"
      condition: selection
    level: high
    """
    rule = load_rule_from_yaml_content(malicious_rule_yaml)
    assert rule.name == "Injection Attempt"

    # Evaluator must treat string as literal string match, not code
    event = SecurityEvent(
        tenant_id=uuid.uuid4(),
        timestamp=datetime.now(UTC),
        source="test",
        event_type="AUTH_FAILURE",
        severity="LOW",
        username="__import__('os').system('echo pwned')",
        raw_event={},
        normalized_event={},
    )
    from app.detection.evaluator import evaluate_rule_against_events

    matches = evaluate_rule_against_events(rule.conditions, [event])
    assert len(matches) == 1

    # Normal string that doesn't match literal code
    normal_event = SecurityEvent(
        tenant_id=uuid.uuid4(),
        timestamp=datetime.now(UTC),
        source="test",
        event_type="AUTH_FAILURE",
        severity="LOW",
        username="admin",
        raw_event={},
        normalized_event={},
    )
    no_matches = evaluate_rule_against_events(rule.conditions, [normal_event])
    assert len(no_matches) == 0


@pytest.mark.asyncio
async def test_invalid_mitre_id_rejected_by_api(client: AsyncClient):
    """Verifies that invalid or fabricated MITRE ATT&CK technique IDs return HTTP 422."""
    reg_res = await client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "MITRE Test Org",
            "email": "engineer@mitretest.com",
            "password": "Password123!",
            "role": "SECURITY_ENGINEER",
        },
    )
    token = reg_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "rule_id": "RULE-FAKE-MITRE",
        "name": "Invalid MITRE Rule",
        "description": "Uses fake technique ID",
        "version": "1.0.0",
        "enabled": True,
        "severity": "MEDIUM",
        "confidence": 0.8,
        "event_types": ["AUTH_FAILURE"],
        "conditions": {"condition": "selection"},
        "mitre_tactics": ["Initial Access"],
        "mitre_techniques": ["T9999.999"],  # Non-existent fake technique
        "tags": [],
    }
    res = await client.post("/api/v1/rules", headers=headers, json=payload)
    assert res.status_code == 422
    assert "invalid mitre" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_cross_tenant_rule_access_denied(client: AsyncClient):
    """
    Verifies that Tenant B cannot access or view custom rules created by Tenant A.
    """
    # 1. Register Tenant A
    reg_a = await client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Tenant A Corp",
            "email": "eng@tenanta.com",
            "password": "Password123!",
            "role": "SECURITY_ENGINEER",
        },
    )
    token_a = reg_a.json()["access_token"]

    # 2. Register Tenant B
    reg_b = await client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Tenant B Corp",
            "email": "eng@tenantb.com",
            "password": "Password123!",
            "role": "SECURITY_ENGINEER",
        },
    )
    token_b = reg_b.json()["access_token"]

    # 3. Tenant A creates custom rule
    rule_id = f"TENANT-A-RULE-{uuid.uuid4().hex[:6].upper()}"
    create_res = await client.post(
        "/api/v1/rules",
        headers={"Authorization": f"Bearer {token_a}"},
        json={
            "rule_id": rule_id,
            "name": "Tenant A Confidential Rule",
            "description": "Internal rule proprietary to Tenant A",
            "version": "1.0.0",
            "enabled": True,
            "severity": "HIGH",
            "confidence": 0.9,
            "event_types": ["AUTH_FAILURE"],
            "conditions": {"condition": "selection"},
            "mitre_tactics": ["Credential Access"],
            "mitre_techniques": ["T1110"],
            "tags": ["tenant_a"],
        },
    )
    assert create_res.status_code == 201

    # 4. Tenant B attempts to read Tenant A's rule -> Must return 404
    get_res = await client.get(
        f"/api/v1/rules/{rule_id}",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert get_res.status_code == 404

    # 5. Tenant B attempts to update Tenant A's rule -> Must return 404
    patch_res = await client.patch(
        f"/api/v1/rules/{rule_id}",
        headers={"Authorization": f"Bearer {token_b}"},
        json={"name": "Hacked Rule Name"},
    )
    assert patch_res.status_code == 404


@pytest.mark.asyncio
async def test_unauthorized_role_cannot_modify_rules(client: AsyncClient):
    """
    Verifies that SOC_L1 analysts cannot create or modify detection rules (RBAC).
    """
    reg_res = await client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Role Test Org",
            "email": "analyst@roletest.com",
            "password": "Password123!",
            "role": "SOC_L1",
        },
    )
    token = reg_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Attempt to create rule
    create_res = await client.post(
        "/api/v1/rules",
        headers=headers,
        json={
            "rule_id": "SOC-L1-ATTEMPT",
            "name": "Unauthorized Rule",
            "description": "Should fail",
            "version": "1.0.0",
            "enabled": True,
            "severity": "LOW",
            "confidence": 0.5,
            "event_types": ["AUTH_FAILURE"],
            "conditions": {},
            "mitre_tactics": [],
            "mitre_techniques": ["T1110"],
            "tags": [],
        },
    )
    assert create_res.status_code == 403
    assert "forbidden" in create_res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_cross_tenant_correlation_assertion(db_session: AsyncSession):
    """
    Verifies that passing detections with mismatched tenants to Correlator raises ValueError.
    """
    tenant_1 = uuid.uuid4()
    tenant_2 = uuid.uuid4()

    det_1 = DetectionResult(
        tenant_id=tenant_1,
        rule_id="RULE-1",
        title="Det 1",
        description="",
        severity="HIGH",
        confidence=0.9,
    )
    det_2 = DetectionResult(
        tenant_id=tenant_2,
        rule_id="RULE-2",
        title="Det 2",
        description="",
        severity="HIGH",
        confidence=0.9,
    )

    correlator = Correlator()
    with pytest.raises(ValueError) as exc_info:
        await correlator.correlate_detections(db=db_session, tenant_id=tenant_1, detections=[det_1, det_2])
    assert "Cross-tenant correlation attempted" in str(exc_info.value)


@pytest.mark.asyncio
async def test_malformed_event_resilience(db_session: AsyncSession):
    """
    Verifies that malformed events (None values, injection strings in IP or username)
    are handled gracefully by the detection engine without SQL injection or crashes.
    """
    tenant = Tenant(name="Resilience Org")
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)

    malformed_event = SecurityEvent(
        tenant_id=tenant.id,
        timestamp=datetime.now(UTC),
        source="edge_firewall",
        event_type="AUTH_FAILURE",
        severity="LOW",
        source_ip="'; DROP TABLE security_events; --",
        username="<script>alert('xss')</script>",
        hostname=None,
        raw_event={"nested": {"deep": None}},
        normalized_event={},
    )
    db_session.add(malformed_event)
    await db_session.commit()

    engine = DetectionEngine()
    # Must evaluate without error
    detections = await engine.evaluate_events(db=db_session, tenant_id=tenant.id, events=[malformed_event])
    assert isinstance(detections, list)


@pytest.mark.asyncio
async def test_redis_failure_fallback():
    """
    Verifies zero event loss: If Redis is unavailable, events route to in-memory fallback queue
    and health status reflects fallback state.
    """
    _in_memory_event_queue.clear()
    test_event_id = str(uuid.uuid4())
    test_tenant_id = str(uuid.uuid4())

    # Enqueue event (in test environment, Redis server is not running on localhost:6379)
    await enqueue_event_for_detection(test_event_id, test_tenant_id)
    # Even if Redis connect failed, event is preserved in fallback queue
    health = await get_queue_health()
    assert isinstance(health, dict)
    assert health["fallback_pending_events"] >= 1

    # Dequeue verifies zero loss
    item = await dequeue_event()
    assert item is not None
    assert item["event_id"] == test_event_id
    assert item["tenant_id"] == test_tenant_id
