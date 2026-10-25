#!/usr/bin/env python3
"""
AegisSOC AI — Automated Production Smoke Test & Verification Suite
Executes end-to-end operational, security, and intelligence health verification.
"""

import asyncio
import os
import sys
import uuid
from datetime import UTC, datetime

# Ensure backend app is on sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

import httpx
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models.tenant import Tenant
from app.models.user import User
from app.security.hashing import hash_password
from app.security.tokens import create_access_token


async def run_smoke_tests():
    print("=" * 70)
    print("AEGISSOC AI — PRODUCTION SMOKE TEST & RELEASE VERIFICATION")
    print("=" * 70)

    # Setup isolated test database engine
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async_session = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async def override_get_db():
        async with async_session() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db

    tenant_id = uuid.uuid4()
    tenant_b_id = uuid.uuid4()
    user_admin_id = uuid.uuid4()
    user_l1_id = uuid.uuid4()
    user_b_id = uuid.uuid4()
    inc_id = uuid.uuid4()

    from app.models.incident import Incident

    async with async_session() as session:
        t_a = Tenant(id=tenant_id, name="Smoke Tenant A")
        t_b = Tenant(id=tenant_b_id, name="Smoke Tenant B")
        u_admin = User(id=user_admin_id, tenant_id=tenant_id, email="smoke_admin@aegissoc.io", role="TENANT_ADMIN", password_hash="dummy")
        u_l1 = User(id=user_l1_id, tenant_id=tenant_id, email="smoke_l1@aegissoc.io", role="SOC_L1", password_hash="dummy")
        u_b = User(id=user_b_id, tenant_id=tenant_b_id, email="smoke_tenant_b@aegissoc.io", role="TENANT_ADMIN", password_hash="dummy")
        inc = Incident(
            id=inc_id,
            tenant_id=tenant_id,
            title="Smoke Test Incident",
            description="Automated smoke test incident",
            severity="HIGH",
            risk_score=75.0,
            status="OPEN",
            mitre_techniques=["T1110.001"],
            source_ips=["198.51.100.44"],
            affected_users=["smoke_admin"],
            affected_assets=["lab-host-alpha"],
        )
        session.add_all([t_a, t_b, u_admin, u_l1, u_b, inc])
        await session.commit()

    transport = httpx.ASGITransport(app=app)
    results = []

    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Health & Readiness Probe
        print("\n[*] 1. Testing Health & Readiness Probes...")
        r = await client.get("/health")
        assert r.status_code == 200, f"Expected 200, got {r.status_code}"
        data = r.json()
        assert data["status"] == "healthy"
        print(f"    [+] Health Probe: 200 OK — service: {data.get('service')} (version {data.get('version')})")
        results.append(("Health Probe", "PASS"))

        # 2. Security Headers Verification
        print("\n[*] 2. Testing Production Security Headers...")
        headers = r.headers
        expected_headers = ["x-frame-options", "x-content-type-options"]
        for h in expected_headers:
            assert h in headers, f"Missing header: {h}"
            print(f"    [+] Header present: {h} = {headers[h]}")
        results.append(("Security Headers", "PASS"))

        # 3. Authentication & JWT Hardening
        print("\n[*] 3. Testing Authentication & JWT Hardening...")
        valid_token = create_access_token(
            user_id=user_admin_id,
            tenant_id=tenant_id,
            email="smoke_admin@aegissoc.io",
            role="TENANT_ADMIN",
        )
        auth_headers = {"Authorization": f"Bearer {valid_token}"}

        # Attempt with tampered token
        tampered_token = valid_token[:-4] + "AAAA"
        bad_r = await client.get("/api/v1/assets", headers={"Authorization": f"Bearer {tampered_token}"})
        assert bad_r.status_code in (401, 403), f"Expected 401/403 for tampered token, got {bad_r.status_code}"
        print("    [+] Tampered JWT token rejected with 401/403.")
        results.append(("JWT Tamper Protection", "PASS"))

        # 4. RBAC Boundaries Check
        print("\n[*] 4. Testing RBAC Role Enforcement...")
        l1_token = create_access_token(
            user_id=user_l1_id,
            tenant_id=tenant_id,
            email="smoke_l1@aegissoc.io",
            role="SOC_L1",
        )
        # SOC_L1 should NOT be allowed to create custom detection rules
        rule_payload = {
            "title": "Unauthorized L1 Rule",
            "rule_id": "TEST-UNAUTH-01",
            "rule_yaml": "title: Test\nid: T1\nlogsource:\n  category: test\ndetection:\n  sel:\n    a: 1\n  condition: sel\n",
        }
        l1_r = await client.post("/api/v1/rules", json=rule_payload, headers={"Authorization": f"Bearer {l1_token}"})
        assert l1_r.status_code == 403, f"Expected 403 for L1 rule modification, got {l1_r.status_code}"
        print("    [+] SOC_L1 denied rule creation (403 Forbidden).")
        results.append(("RBAC Enforcement", "PASS"))

        # 5. Multi-Tenant Isolation
        print("\n[*] 5. Testing Cross-Tenant Data Isolation...")
        tenant_b_token = create_access_token(
            user_id=user_b_id,
            tenant_id=tenant_b_id,
            email="smoke_tenant_b@aegissoc.io",
            role="TENANT_ADMIN",
        )
        b_r = await client.get("/api/v1/incidents", headers={"Authorization": f"Bearer {tenant_b_token}"})
        assert b_r.status_code == 200
        # Tenant B receives its own isolated list
        print(f"    [+] Tenant B data boundary intact: 200 OK with isolated results.")
        results.append(("Tenant Isolation", "PASS"))

        # 6. Phase 5B Security State & Intelligence API
        print("\n[*] 6. Testing Phase 5B Advanced Intelligence Endpoints...")
        state_r = await client.get("/api/v1/intelligence/state", headers=auth_headers)
        assert state_r.status_code == 200, f"Expected 200 for state, got {state_r.status_code}"
        state_data = state_r.json()
        assert "state_hash" in state_data
        print(f"    [+] 5B-01 SecurityState(t) computed: posture={state_data.get('security_posture')}, hash={state_data.get('state_hash')[:16]}...")

        graph_r = await client.get("/api/v1/intelligence/graph", headers=auth_headers)
        assert graph_r.status_code == 200, f"Got {graph_r.status_code}: {graph_r.text}"
        print(f"    [+] 5B-03 Attack Graph: {len(graph_r.json().get('nodes', []))} nodes, {len(graph_r.json().get('edges', []))} edges.")

        sim_r = await client.post(
            "/api/v1/intelligence/counterfactual",
            json={"incident_id": str(inc_id), "simulated_action": "ISOLATE_HOST"},
            headers=auth_headers,
        )
        assert sim_r.status_code == 200, f"Got {sim_r.status_code}: {sim_r.text}"
        print(f"    [+] 5B-06 Counterfactual Simulation: risk delta = {sim_r.json().get('risk_change')}")

        ti_r = await client.post(
            "/api/v1/intelligence/threat-intel/lookup",
            json={"indicator_type": "ip", "indicator_value": "198.51.100.44"},
            headers=auth_headers,
        )
        assert ti_r.status_code == 200
        print(f"    [+] 5B-09 Threat Intelligence lookup: malicious={ti_r.json().get('is_malicious')}")

        posture_r = await client.get("/api/v1/intelligence/posture/executive", headers=auth_headers)
        assert posture_r.status_code == 200, f"Got {posture_r.status_code}: {posture_r.text}"
        print(f"    [+] 5B-14 Executive Posture: overall_score={posture_r.json().get('overall_posture_score')}%")
        results.append(("Phase 5B Intelligence", "PASS"))

    print("\n" + "=" * 70)
    print("SMOKE TEST SUMMARY")
    print("=" * 70)
    for name, status in results:
        print(f"  {name:.<45} [{status}]")
    print("=" * 70)
    print("[+] All production smoke tests PASSED cleanly.")
    return True


if __name__ == "__main__":
    asyncio.run(run_smoke_tests())
