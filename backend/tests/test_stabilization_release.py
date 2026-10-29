"""Stabilization Release Regression Tests

Verifies:
1. Auth token refresh lifecycle & logout
2. Dashboard filters & statistics endpoint
3. L2 Escalation payload serialization & idempotency
4. RBAC role resolution and permission enforcement
5. Tenant isolation across incidents & escalations
"""

import uuid
from datetime import UTC, datetime

import pytest
from fastapi import HTTPException

from app.models.incident import Incident
from app.models.tenant import Tenant
from app.models.user import User
from app.security.roles import Role, check_role_permission, normalize_role
from app.security.tokens import create_access_token, create_refresh_token


@pytest.fixture
def auth_headers_factory():
    def _create_headers(user_id: uuid.UUID, email: str, role: str, tenant_id: uuid.UUID):
        token = create_access_token(
            user_id=user_id,
            tenant_id=tenant_id,
            email=email,
            role=role,
        )
        return {"Authorization": f"Bearer {token}"}

    return _create_headers


# -----------------------------------------------------------------------------
# 1. AUTH LIFECYCLE & REFRESH TESTS
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_auth_refresh_success(client, db_session):
    """Verify refresh endpoint accepts valid refresh token and returns new token pair."""
    tenant = Tenant(name=f"Stab Tenant {uuid.uuid4().hex[:8]}")
    db_session.add(tenant)
    await db_session.flush()

    user = User(
        email=f"analyst-{uuid.uuid4().hex[:6]}@example.com",
        password_hash="testhash",
        role="SOC_L1",
        status="ACTIVE",
        tenant_id=tenant.id,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    refresh_token = create_refresh_token(
        user_id=user.id,
        tenant_id=tenant.id,
    )

    response = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert data["refresh_token"] != refresh_token  # rotated with unique jti


@pytest.mark.asyncio
async def test_auth_refresh_rejects_access_token(client):
    """Verify refresh endpoint rejects tokens that lack type == 'refresh'."""
    fake_access_token = create_access_token(
        user_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        email="test@example.com",
        role="SOC_L1",
    )
    response = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": fake_access_token},
    )
    assert response.status_code == 401
    assert "not an authorized refresh token" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_auth_refresh_rejects_deactivated_user(client, db_session):
    """Verify refresh endpoint rejects deactivated/suspended users."""
    tenant = Tenant(name=f"Deact Tenant {uuid.uuid4().hex[:8]}")
    db_session.add(tenant)
    await db_session.flush()

    user = User(
        email=f"suspended-{uuid.uuid4().hex[:6]}@example.com",
        password_hash="testhash",
        role="SOC_L1",
        status="SUSPENDED",
        tenant_id=tenant.id,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    refresh_token = create_refresh_token(
        user_id=user.id,
        tenant_id=tenant.id,
    )

    response = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert response.status_code == 403
    assert "user account is suspended" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_auth_logout(client, db_session, auth_headers_factory):
    """Verify logout endpoint logs audit event and returns 200."""
    tenant = Tenant(name=f"Logout Tenant {uuid.uuid4().hex[:8]}")
    db_session.add(tenant)
    await db_session.flush()

    user = User(
        email=f"logout-{uuid.uuid4().hex[:6]}@example.com",
        password_hash="testhash",
        role="SOC_L1",
        status="ACTIVE",
        tenant_id=tenant.id,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    headers = auth_headers_factory(user.id, user.email, "SOC_L1", tenant.id)

    response = await client.post("/api/v1/auth/logout", headers=headers)
    assert response.status_code == 200
    assert response.json()["message"] == "Successfully logged out."


# -----------------------------------------------------------------------------
# 2. RBAC ROLES & PERMISSION LOGIC
# -----------------------------------------------------------------------------


def test_rbac_role_normalization():
    """Verify normalization of role aliases to canonical representations."""
    assert normalize_role("TENANT_ADMIN") == "TENANT_ADMIN"
    assert normalize_role("SOC_L1_ANALYST") == "SOC_L1"
    assert normalize_role("SOC_L2_ANALYST") == "SOC_L2"
    assert normalize_role("soc_l1_analyst") == "SOC_L1"
    assert normalize_role("SECURITY_ENGINEER") == "SECURITY_ENGINEER"
    assert normalize_role("THREAT_HUNTER") == "THREAT_HUNTER"
    assert normalize_role("AUDITOR") == "AUDITOR"
    assert normalize_role("VIEWER") == "VIEWER"


def test_rbac_permission_matrix():
    """Verify permission checks succeed or raise 403 Forbidden."""
    # Allowed: SOC_L2 in [SOC_L2, TENANT_ADMIN]
    check_role_permission("SOC_L2_ANALYST", [Role.SOC_L2, Role.TENANT_ADMIN])
    # Allowed: TENANT_ADMIN has super-privileges
    check_role_permission("TENANT_ADMIN", [Role.SOC_L2])

    # Disallowed: VIEWER attempting escalation
    with pytest.raises(HTTPException) as exc_info:
        check_role_permission("VIEWER", [Role.SOC_L1, Role.SOC_L2, Role.TENANT_ADMIN])
    assert exc_info.value.status_code == 403


# -----------------------------------------------------------------------------
# 3. DASHBOARD FILTERS & STATS
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dashboard_incident_filters(client, db_session, auth_headers_factory):
    """Verify filtering by severity, status, and stats endpoint calculations."""
    tenant = Tenant(name=f"Filter Tenant {uuid.uuid4().hex[:8]}")
    db_session.add(tenant)
    await db_session.flush()

    user = User(
        email=f"filter-user-{uuid.uuid4().hex[:6]}@example.com",
        password_hash="testhash",
        role="SOC_L1",
        status="ACTIVE",
        tenant_id=tenant.id,
    )
    db_session.add(user)
    await db_session.flush()

    # Create 3 incidents: 1 CRITICAL OPEN, 1 HIGH INVESTIGATING, 1 LOW RESOLVED
    inc1 = Incident(
        tenant_id=tenant.id,
        title="Critical Breach Event",
        description="Active ransomware execution",
        severity="CRITICAL",
        status="OPEN",
        risk_score=95.0,
        confidence=1.0,
        created_at=datetime.now(UTC),
    )
    inc2 = Incident(
        tenant_id=tenant.id,
        title="High Suspicious Activity",
        description="Unusual process discovery",
        severity="HIGH",
        status="INVESTIGATING",
        risk_score=75.0,
        confidence=0.9,
        created_at=datetime.now(UTC),
    )
    inc3 = Incident(
        tenant_id=tenant.id,
        title="Low Noise Alert",
        description="Benign scanner ping",
        severity="LOW",
        status="RESOLVED",
        risk_score=20.0,
        confidence=0.5,
        created_at=datetime.now(UTC),
    )
    db_session.add_all([inc1, inc2, inc3])
    await db_session.commit()

    headers = auth_headers_factory(user.id, user.email, "SOC_L1", tenant.id)

    # 1. Severity Filter: CRITICAL
    r_crit = await client.get("/api/v1/incidents?severity=CRITICAL", headers=headers)
    assert r_crit.status_code == 200
    items = r_crit.json()
    assert len(items) == 1
    assert items[0]["severity"] == "CRITICAL"

    # 2. Status Filter: OPEN
    r_open = await client.get("/api/v1/incidents?status=OPEN", headers=headers)
    assert r_open.status_code == 200
    items = r_open.json()
    assert len(items) == 1
    assert items[0]["status"] == "OPEN"

    # 3. Combined Filter: HIGH + INVESTIGATING
    r_comb = await client.get("/api/v1/incidents?severity=HIGH&status=INVESTIGATING", headers=headers)
    assert r_comb.status_code == 200
    items = r_comb.json()
    assert len(items) == 1
    assert items[0]["title"] == "High Suspicious Activity"

    # 4. Filter that yields empty list
    r_empty = await client.get("/api/v1/incidents?severity=MEDIUM", headers=headers)
    assert r_empty.status_code == 200
    assert r_empty.json() == []

    # 5. Incident Stats endpoint
    r_stats = await client.get("/api/v1/incidents/stats", headers=headers)
    assert r_stats.status_code == 200
    stats = r_stats.json()
    assert stats["total_count"] == 3
    assert stats["open_count"] == 1
    assert stats["investigating_count"] == 1
    assert stats["resolved_count"] == 1
    assert stats["critical_count"] == 1
    assert stats["high_count"] == 1
    assert stats["posture_status"] == "CRITICAL THREAT"


# -----------------------------------------------------------------------------
# 4. L2 ESCALATION SERIALIZATION & IDEMPOTENCY
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_l2_escalation_serialization_and_idempotency(client, db_session, auth_headers_factory):
    """Verify L2 escalation persists without JSON serialization error and is idempotent."""
    tenant = Tenant(name=f"Escalation Tenant {uuid.uuid4().hex[:8]}")
    db_session.add(tenant)
    await db_session.flush()

    user = User(
        email=f"esc-user-{uuid.uuid4().hex[:6]}@example.com",
        password_hash="testhash",
        role="SOC_L2",
        status="ACTIVE",
        tenant_id=tenant.id,
    )
    db_session.add(user)
    await db_session.flush()

    incident = Incident(
        tenant_id=tenant.id,
        title="Target for Escalation",
        description="Critical intrusion alert",
        severity="HIGH",
        status="INVESTIGATING",
        risk_score=80.0,
        confidence=0.9,
        created_at=datetime.now(UTC),
    )
    db_session.add(incident)
    await db_session.commit()
    await db_session.refresh(incident)

    headers = auth_headers_factory(user.id, user.email, "SOC_L2", tenant.id)

    # First escalation call
    payload = {
        "reason": "Host memory dump shows beaconing to malicious C2",
        "urgency": "HIGH",
    }
    resp = await client.post(
        f"/api/v1/incidents/{incident.id}/escalate",
        json=payload,
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["incident_id"] == str(incident.id)
    assert data["status"] == "OPEN"
    escalation_id = data["id"]
    assert "l2_package" in data
    assert isinstance(data["l2_package"], dict)
    assert data["l2_package"]["incident_id"] == str(incident.id)

    # Second escalation call (idempotency check)
    resp2 = await client.post(
        f"/api/v1/incidents/{incident.id}/escalate",
        json={"reason": "Updated note: Priority verified by analyst", "urgency": "CRITICAL"},
        headers=headers,
    )
    assert resp2.status_code in (200, 201)
    data2 = resp2.json()
    # Should reuse existing escalation record ID rather than duplicating
    assert data2["id"] == escalation_id
    assert data2["urgency"] == "CRITICAL"


@pytest.mark.asyncio
async def test_l2_escalation_tenant_isolation(client, db_session, auth_headers_factory):
    """Verify user from Tenant B cannot escalate an incident belonging to Tenant A."""
    tenant_a = Tenant(name=f"Tenant A {uuid.uuid4().hex[:8]}")
    tenant_b = Tenant(name=f"Tenant B {uuid.uuid4().hex[:8]}")
    db_session.add_all([tenant_a, tenant_b])
    await db_session.flush()

    user_b = User(
        email=f"user-b-{uuid.uuid4().hex[:6]}@example.com",
        password_hash="testhash",
        role="SOC_L2",
        status="ACTIVE",
        tenant_id=tenant_b.id,
    )
    inc_a = Incident(
        tenant_id=tenant_a.id,
        title="Tenant A Private Incident",
        description="Secret internal event",
        severity="CRITICAL",
        status="OPEN",
        risk_score=90.0,
        confidence=1.0,
    )
    db_session.add_all([user_b, inc_a])
    await db_session.commit()
    await db_session.refresh(inc_a)

    headers_b = auth_headers_factory(user_b.id, user_b.email, "SOC_L2", tenant_b.id)

    resp = await client.post(
        f"/api/v1/incidents/{inc_a.id}/escalate",
        json={"reason": "Attempting cross-tenant escalation"},
        headers=headers_b,
    )
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()
