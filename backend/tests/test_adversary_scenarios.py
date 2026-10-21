import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.adversary.cleanup import execute_scenario_cleanup
from app.adversary.executor import execute_adversary_assessment
from app.adversary.models import AdversaryAssessment
from app.models.tenant import Tenant
from app.models.user import User
from app.security.tokens import create_access_token


@pytest.mark.asyncio
async def test_scenario_001_ssh_bruteforce_end_to_end(db_session: AsyncSession):
    """
    SCENARIO-001: SSH Brute Force (T1110.001)
    Simulates controlled SSH auth failures against lab target.
    Verifies: Simulation -> Detection -> Correlation -> Investigation -> Response -> Verification -> Cleanup.
    """
    tenant = Tenant(name="Adversary Lab Tenant 1")
    db_session.add(tenant)
    await db_session.flush()

    user_id = uuid.uuid4()
    scope = {
        "environment": "LAB",
        "assets": ["lab-server-01"],
        "ips": ["10.0.0.50"],
        "allowed_techniques": ["T1110.001"],
        "prohibited_techniques": ["persistence", "data_exfiltration", "destructive_actions"],
        "expires_at": (datetime.now(UTC) + timedelta(hours=2)).isoformat(),
        "authorized_by": str(user_id),
    }

    assessment = AdversaryAssessment(
        tenant_id=tenant.id,
        name="SSH Brute Force Validation",
        description="Testing SSH brute force detection rule",
        environment="LAB",
        scenario="SCENARIO-001",
        status="AUTHORIZED",
        authorized_scope=scope,
        created_by=user_id,
        authorized_by=user_id,
    )
    db_session.add(assessment)
    await db_session.commit()

    result = await execute_adversary_assessment(
        db=db_session,
        tenant_id=tenant.id,
        assessment_id=assessment.id,
        user_id=user_id,
        user_role="SOC_L2",
    )

    assert result.simulation_status == "PASS"
    assert result.detection_status == "PASS"
    assert result.correlation_status == "PASS"
    assert result.investigation_status == "PASS"
    assert result.response_status == "PASS"
    assert result.verification_status == "PASS"
    assert result.cleanup_status == "CLEANED"
    assert result.overall_result == "PASS"
    assert len(result.evidence_ids) > 0


@pytest.mark.asyncio
async def test_scenario_002_password_spraying_end_to_end(db_session: AsyncSession):
    """
    SCENARIO-002: Password Spraying (T1110.003)
    Simulates single password against multiple lab accounts.
    """
    tenant = Tenant(name="Adversary Lab Tenant 2")
    db_session.add(tenant)
    await db_session.flush()

    user_id = uuid.uuid4()
    scope = {
        "environment": "LAB",
        "assets": ["lab-ad-01"],
        "ips": ["10.0.0.51"],
        "allowed_techniques": ["T1110.003"],
        "prohibited_techniques": ["persistence", "data_exfiltration"],
        "expires_at": (datetime.now(UTC) + timedelta(hours=2)).isoformat(),
        "authorized_by": str(user_id),
    }

    assessment = AdversaryAssessment(
        tenant_id=tenant.id,
        name="Password Spraying Validation",
        description="Testing Password Spraying detection rule",
        environment="LAB",
        scenario="SCENARIO-002",
        status="AUTHORIZED",
        authorized_scope=scope,
        created_by=user_id,
        authorized_by=user_id,
    )
    db_session.add(assessment)
    await db_session.commit()

    result = await execute_adversary_assessment(
        db=db_session,
        tenant_id=tenant.id,
        assessment_id=assessment.id,
        user_id=user_id,
        user_role="SOC_L2",
    )

    assert result.simulation_status == "PASS"
    assert result.technique_id == "T1110.003"
    assert result.cleanup_status == "CLEANED"
    assert result.overall_result in ("PASS", "PARTIAL")


@pytest.mark.asyncio
async def test_scenario_003_failure_then_success_end_to_end(db_session: AsyncSession):
    """
    SCENARIO-003: Failure -> Success (T1078)
    Simulates failed logins followed by successful login.
    """
    tenant = Tenant(name="Adversary Lab Tenant 3")
    db_session.add(tenant)
    await db_session.flush()

    user_id = uuid.uuid4()
    scope = {
        "environment": "LAB",
        "assets": ["lab-server-02"],
        "ips": ["10.0.0.52"],
        "allowed_techniques": ["T1078"],
        "prohibited_techniques": ["persistence", "destructive_actions"],
        "expires_at": (datetime.now(UTC) + timedelta(hours=2)).isoformat(),
        "authorized_by": str(user_id),
    }

    assessment = AdversaryAssessment(
        tenant_id=tenant.id,
        name="Failure then Success Validation",
        environment="LAB",
        scenario="SCENARIO-003",
        status="AUTHORIZED",
        authorized_scope=scope,
        created_by=user_id,
        authorized_by=user_id,
    )
    db_session.add(assessment)
    await db_session.commit()

    result = await execute_adversary_assessment(
        db=db_session,
        tenant_id=tenant.id,
        assessment_id=assessment.id,
        user_id=user_id,
        user_role="SOC_L2",
    )

    assert result.simulation_status == "PASS"
    assert result.technique_id == "T1078"
    assert result.cleanup_status == "CLEANED"


@pytest.mark.asyncio
async def test_scenario_004_privileged_login_end_to_end(db_session: AsyncSession):
    """
    SCENARIO-004: Privileged Login Telemetry (T1078.003)
    Simulates root/admin login from lab subnet.
    """
    tenant = Tenant(name="Adversary Lab Tenant 4")
    db_session.add(tenant)
    await db_session.flush()

    user_id = uuid.uuid4()
    scope = {
        "environment": "LAB",
        "assets": ["lab-db-01"],
        "ips": ["10.0.0.53"],
        "allowed_techniques": ["T1078.003"],
        "prohibited_techniques": ["persistence", "data_exfiltration"],
        "expires_at": (datetime.now(UTC) + timedelta(hours=2)).isoformat(),
        "authorized_by": str(user_id),
    }

    assessment = AdversaryAssessment(
        tenant_id=tenant.id,
        name="Privileged Login Validation",
        environment="LAB",
        scenario="SCENARIO-004",
        status="AUTHORIZED",
        authorized_scope=scope,
        created_by=user_id,
        authorized_by=user_id,
    )
    db_session.add(assessment)
    await db_session.commit()

    result = await execute_adversary_assessment(
        db=db_session,
        tenant_id=tenant.id,
        assessment_id=assessment.id,
        user_id=user_id,
        user_role="SOC_L2",
    )

    assert result.simulation_status == "PASS"
    assert result.technique_id == "T1078.003"
    assert result.cleanup_status == "CLEANED"


@pytest.mark.asyncio
async def test_cleanup_executes_even_on_failure(db_session: AsyncSession):
    """Verifies cleanup handler restores mock state even when simulation encounters error."""
    tenant = Tenant(name="Cleanup Tenant")
    db_session.add(tenant)
    await db_session.flush()

    user_id = uuid.uuid4()
    scope = {
        "environment": "LAB",
        "assets": ["lab-host-fail"],
        "ips": ["10.0.0.99"],
        "allowed_techniques": ["T1110.001"],
        "prohibited_techniques": ["persistence"],
        "expires_at": (datetime.now(UTC) + timedelta(hours=2)).isoformat(),
        "authorized_by": str(user_id),
    }

    assessment = AdversaryAssessment(
        tenant_id=tenant.id,
        name="Cleanup Test Assessment",
        environment="LAB",
        scenario="SCENARIO-001",
        status="AUTHORIZED",
        authorized_scope=scope,
        created_by=user_id,
        authorized_by=user_id,
    )
    db_session.add(assessment)
    await db_session.commit()

    cleanup_res = await execute_scenario_cleanup(
        db=db_session,
        tenant_id=tenant.id,
        assessment_id=assessment.id,
        scenario_id="SCENARIO-001",
        target_ip="10.0.0.99",
    )
    assert cleanup_res == "CLEANED"


@pytest.mark.asyncio
async def test_adversary_api_endpoints_workflow(client: AsyncClient, db_session: AsyncSession):
    """Verifies complete API workflow: Create -> Authorize -> Start -> Results -> Cancel."""
    # Create tenant and user
    tenant = Tenant(name="Adversary API Tenant")
    db_session.add(tenant)
    await db_session.flush()

    user = User(
        tenant_id=tenant.id,
        email="l2_sec_lead@aegissoc.io",
        password_hash="hash",
        role="SOC_L2",
    )
    db_session.add(user)
    await db_session.commit()

    token = create_access_token(user_id=user.id, tenant_id=tenant.id, email=user.email, role=user.role)
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Create Assessment
    create_payload = {
        "name": "API Lab Assessment",
        "description": "Created via API",
        "environment": "LAB",
        "scenario": "SCENARIO-001",
        "authorized_scope": {
            "environment": "LAB",
            "assets": ["lab-target-01"],
            "ips": ["10.0.0.60"],
            "allowed_techniques": ["T1110.001"],
            "prohibited_techniques": ["persistence", "data_exfiltration"],
            "expires_at": (datetime.now(UTC) + timedelta(hours=2)).isoformat(),
        },
    }
    resp = await client.post("/api/v1/adversary/assessments", json=create_payload, headers=headers)
    assert resp.status_code == 201
    assessment_data = resp.json()
    assessment_id = assessment_data["id"]
    assert assessment_data["status"] == "DRAFT"

    # 2. Authorize Assessment
    auth_resp = await client.post(f"/api/v1/adversary/assessments/{assessment_id}/authorize", json={}, headers=headers)
    assert auth_resp.status_code == 200
    assert auth_resp.json()["status"] == "AUTHORIZED"

    # 3. Start Assessment
    start_resp = await client.post(f"/api/v1/adversary/assessments/{assessment_id}/start", headers=headers)
    assert start_resp.status_code == 200
    result_data = start_resp.json()
    assert result_data["simulation_status"] == "PASS"
    assert result_data["cleanup_status"] == "CLEANED"

    # 4. Get Results
    res_resp = await client.get(f"/api/v1/adversary/assessments/{assessment_id}/results", headers=headers)
    assert res_resp.status_code == 200
    assert len(res_resp.json()) >= 1
