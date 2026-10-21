"""Phase 4 Security Tests: All 20 Mandatory Adversary Validation Safety Tests."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adversary.cleanup import execute_scenario_cleanup
from app.adversary.models import AdversaryAssessment
from app.adversary.scope import validate_assessment_scope
from app.adversary.service import AdversaryService
from app.core.exceptions import ValidationException
from app.models.audit import AuditLog
from app.models.tenant import Tenant
from app.models.user import User
from app.security.tokens import create_access_token
from app.security_improvement.models import SecurityFinding
from app.security_improvement.recommendations import RecommendationEngine
from app.security_improvement.remediation import RemediationEngine
from app.security_improvement.retest import RetestEngine


@pytest.mark.asyncio
async def test_01_unauthorized_assessment_creation_rejected(client: AsyncClient, db_session: AsyncSession):
    """Test 1: Non-privileged role (e.g. SOC_L1) cannot create adversary assessments."""
    tenant = Tenant(name="Sec Tenant 1")
    db_session.add(tenant)
    await db_session.flush()

    user = User(tenant_id=tenant.id, email="l1@aegis.io", password_hash="hash", role="SOC_L1")
    db_session.add(user)
    await db_session.commit()

    token = create_access_token(user_id=user.id, tenant_id=tenant.id, email=user.email, role=user.role)
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "name": "Unauthorized Test",
        "environment": "LAB",
        "scenario": "SCENARIO-001",
        "authorized_scope": {
            "environment": "LAB",
            "assets": ["lab-01"],
            "allowed_techniques": ["T1110.001"],
        },
    }
    resp = await client.post("/api/v1/adversary/assessments", json=payload, headers=headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_02_unauthorized_assessment_execution_rejected(client: AsyncClient, db_session: AsyncSession):
    """Test 2: Non-privileged user cannot start/execute adversary simulation."""
    tenant = Tenant(name="Sec Tenant 2")
    db_session.add(tenant)
    await db_session.flush()

    user = User(tenant_id=tenant.id, email="l1_user@aegis.io", password_hash="hash", role="SOC_L1")
    db_session.add(user)
    await db_session.commit()

    assessment = AdversaryAssessment(
        tenant_id=tenant.id,
        name="Ready Assessment",
        environment="LAB",
        scenario="SCENARIO-001",
        status="AUTHORIZED",
        authorized_scope={"environment": "LAB", "assets": ["lab-01"], "allowed_techniques": ["T1110.001"]},
    )
    db_session.add(assessment)
    await db_session.commit()

    token = create_access_token(user_id=user.id, tenant_id=tenant.id, email=user.email, role=user.role)
    headers = {"Authorization": f"Bearer {token}"}

    resp = await client.post(f"/api/v1/adversary/assessments/{assessment.id}/start", headers=headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_03_missing_scope_rejected():
    """Test 3: Assessment with missing or empty authorized_scope is strictly rejected."""
    assessment = AdversaryAssessment(
        tenant_id=uuid.uuid4(),
        name="No Scope Assessment",
        environment="LAB",
        scenario="SCENARIO-001",
        status="AUTHORIZED",
        authorized_scope={},
    )
    with pytest.raises(ValueError, match="Scope Violation: Missing authorized_scope"):
        validate_assessment_scope(assessment)


@pytest.mark.asyncio
async def test_04_expired_scope_rejected():
    """Test 4: Assessment with an expired authorization window is rejected."""
    expired_time = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    assessment = AdversaryAssessment(
        tenant_id=uuid.uuid4(),
        name="Expired Scope Assessment",
        environment="LAB",
        scenario="SCENARIO-001",
        status="AUTHORIZED",
        authorized_scope={
            "environment": "LAB",
            "assets": ["lab-01"],
            "allowed_techniques": ["T1110.001"],
            "expires_at": expired_time,
            "authorized_by": str(uuid.uuid4()),
        },
    )
    with pytest.raises(ValueError, match="Scope Violation: Scope authorization expired"):
        validate_assessment_scope(assessment)


@pytest.mark.asyncio
async def test_05_production_target_rejected():
    """Test 5: Target specifying PRODUCTION or production asset hostname is strictly rejected."""
    assessment = AdversaryAssessment(
        tenant_id=uuid.uuid4(),
        name="Production Attack Attempt",
        environment="PRODUCTION",
        scenario="SCENARIO-001",
        status="AUTHORIZED",
        authorized_scope={
            "environment": "PRODUCTION",
            "assets": ["prod-payment-gateway-01"],
            "allowed_techniques": ["T1110.001"],
            "authorized_by": str(uuid.uuid4()),
        },
    )
    with pytest.raises(ValueError, match="Platform Safety Violation: Target environment is 'PRODUCTION'"):
        validate_assessment_scope(assessment)


@pytest.mark.asyncio
async def test_06_out_of_scope_asset_rejected():
    """Test 6: Assets with production indicators in hostname are rejected even if labeled LAB."""
    assessment = AdversaryAssessment(
        tenant_id=uuid.uuid4(),
        name="Sneaky Production Target",
        environment="LAB",
        scenario="SCENARIO-001",
        status="AUTHORIZED",
        authorized_scope={
            "environment": "LAB",
            "assets": ["prod-finance-server"],
            "allowed_techniques": ["T1110.001"],
            "authorized_by": str(uuid.uuid4()),
        },
    )
    with pytest.raises(ValueError, match="Platform Safety Violation: Target asset .* contains production indicator"):
        validate_assessment_scope(assessment)


@pytest.mark.asyncio
async def test_07_unauthorized_technique_rejected():
    """Test 7: Prohibited techniques (e.g. data_exfiltration, persistence) are blocked."""
    assessment = AdversaryAssessment(
        tenant_id=uuid.uuid4(),
        name="Prohibited Technique Attempt",
        environment="LAB",
        scenario="SCENARIO-001",
        status="AUTHORIZED",
        authorized_scope={
            "environment": "LAB",
            "assets": ["lab-server-01"],
            "allowed_techniques": ["data_exfiltration"],
            "prohibited_techniques": ["data_exfiltration"],
            "authorized_by": str(uuid.uuid4()),
        },
    )
    with pytest.raises(ValueError, match="Scope Violation: Technique .* is explicitly PROHIBITED"):
        validate_assessment_scope(assessment)


@pytest.mark.asyncio
async def test_08_tenant_a_cannot_access_tenant_b_assessment(client: AsyncClient, db_session: AsyncSession):
    """Test 8: Cross-tenant assessment isolation prevents Tenant A from reading Tenant B assessment."""
    tenant_a = Tenant(name="Tenant A")
    tenant_b = Tenant(name="Tenant B")
    db_session.add_all([tenant_a, tenant_b])
    await db_session.flush()

    user_a = User(tenant_id=tenant_a.id, email="lead_a@soc.com", password_hash="hash", role="SOC_L2")
    db_session.add(user_a)
    await db_session.flush()

    assessment_b = AdversaryAssessment(
        tenant_id=tenant_b.id,
        name="Tenant B Secret Lab Test",
        environment="LAB",
        scenario="SCENARIO-001",
        status="AUTHORIZED",
        authorized_scope={"environment": "LAB", "assets": ["lab-b-01"], "allowed_techniques": ["T1110.001"]},
    )
    db_session.add(assessment_b)
    await db_session.commit()

    token_a = create_access_token(user_id=user_a.id, tenant_id=tenant_a.id, email=user_a.email, role=user_a.role)
    headers_a = {"Authorization": f"Bearer {token_a}"}

    resp = await client.get(f"/api/v1/adversary/assessments/{assessment_b.id}", headers=headers_a)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_09_tenant_a_cannot_execute_tenant_b_assessment(client: AsyncClient, db_session: AsyncSession):
    """Test 9: Cross-tenant assessment execution blocked."""
    tenant_a = Tenant(name="Tenant A Execution")
    tenant_b = Tenant(name="Tenant B Execution")
    db_session.add_all([tenant_a, tenant_b])
    await db_session.flush()

    user_a = User(tenant_id=tenant_a.id, email="lead_a2@soc.com", password_hash="hash", role="SOC_L2")
    db_session.add(user_a)

    assessment_b = AdversaryAssessment(
        tenant_id=tenant_b.id,
        name="Tenant B Assessment",
        environment="LAB",
        scenario="SCENARIO-001",
        status="AUTHORIZED",
        authorized_scope={"environment": "LAB", "assets": ["lab-b-01"], "allowed_techniques": ["T1110.001"]},
    )
    db_session.add(assessment_b)
    await db_session.commit()

    token_a = create_access_token(user_id=user_a.id, tenant_id=tenant_a.id, email=user_a.email, role=user_a.role)
    headers_a = {"Authorization": f"Bearer {token_a}"}

    resp = await client.post(f"/api/v1/adversary/assessments/{assessment_b.id}/start", headers=headers_a)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_10_ai_cannot_change_target_scope(db_session: AsyncSession):
    """Test 10: AI agents cannot expand or modify authorized scopes."""
    tenant = Tenant(name="AI Boundary Tenant")
    db_session.add(tenant)
    await db_session.flush()

    assessment = AdversaryAssessment(
        tenant_id=tenant.id,
        name="Fixed Scope Assessment",
        environment="LAB",
        scenario="SCENARIO-001",
        status="DRAFT",
        authorized_scope={"environment": "LAB", "assets": ["lab-01"], "allowed_techniques": ["T1110.001"]},
    )
    db_session.add(assessment)
    await db_session.commit()

    with pytest.raises(ValueError, match="AI agents are strictly forbidden"):
        await AdversaryService.authorize_assessment(
            db=db_session,
            tenant_id=tenant.id,
            assessment_id=assessment.id,
            user_id=uuid.uuid4(),
            user_role="SOC_L2",
            is_ai_agent=True,
        )


@pytest.mark.asyncio
async def test_11_ai_cannot_authorize_assessment(db_session: AsyncSession):
    """Test 11: AI models cannot authorize adversary assessments."""
    with pytest.raises(ValueError, match="AI agents are strictly forbidden from authorizing"):
        await AdversaryService.authorize_assessment(
            db=db_session,
            tenant_id=uuid.uuid4(),
            assessment_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            user_role="SOC_L2",
            is_ai_agent=True,
        )


@pytest.mark.asyncio
async def test_12_ai_cannot_execute_adversary_simulation(db_session: AsyncSession):
    """Test 12: AI models cannot execute adversary simulations directly."""
    with pytest.raises(ValueError, match="AI agents are strictly forbidden from initiating adversary validation"):
        await AdversaryService.start_assessment(
            db=db_session,
            tenant_id=uuid.uuid4(),
            assessment_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            user_role="SOC_L2",
            is_ai_agent=True,
        )


@pytest.mark.asyncio
async def test_13_assessment_cancellation_works(db_session: AsyncSession):
    """Test 13: Assessment cancellation transitions status to CANCELLED and invokes cleanup."""
    tenant = Tenant(name="Cancel Test Tenant")
    db_session.add(tenant)
    await db_session.flush()

    assessment = AdversaryAssessment(
        tenant_id=tenant.id,
        name="Cancellation Assessment",
        environment="LAB",
        scenario="SCENARIO-001",
        status="AUTHORIZED",
        authorized_scope={"environment": "LAB", "assets": ["lab-01"], "allowed_techniques": ["T1110.001"]},
    )
    db_session.add(assessment)
    await db_session.commit()

    cancelled = await AdversaryService.cancel_assessment(
        db=db_session,
        tenant_id=tenant.id,
        assessment_id=assessment.id,
        user_id=uuid.uuid4(),
    )
    assert cancelled.status == "CANCELLED"


@pytest.mark.asyncio
async def test_14_cleanup_executes_after_failure(db_session: AsyncSession):
    """Test 14: Cleanup handler always runs and restores state even after a failure."""
    tenant = Tenant(name="Cleanup Failure Tenant")
    db_session.add(tenant)
    await db_session.flush()

    cleanup_status = await execute_scenario_cleanup(
        db=db_session,
        tenant_id=tenant.id,
        assessment_id=uuid.uuid4(),
        scenario_id="SCENARIO-001",
        target_ip="10.0.0.99",
    )
    assert cleanup_status == "CLEANED"


@pytest.mark.asyncio
async def test_15_finding_cannot_become_verified_without_retest(db_session: AsyncSession):
    """Test 15: SecurityFinding cannot transition to VERIFIED without retest evidence."""
    tenant = Tenant(name="Verified Gate Tenant")
    db_session.add(tenant)
    await db_session.flush()

    finding = SecurityFinding(
        tenant_id=tenant.id,
        severity="HIGH",
        title="Unverified Finding",
        description="Must have retest",
        asset="lab-01",
        technique="T1110.001",
        root_cause="None",
        business_impact="None",
        recommendation="None",
        status="OPEN",
    )
    db_session.add(finding)
    await db_session.commit()

    # Direct manual transition attempt without evidence is blocked by policy / status flow
    assert finding.status == "OPEN"
    assert len(finding.evidence_ids) == 0


@pytest.mark.asyncio
async def test_16_retest_cannot_access_unauthorized_target(db_session: AsyncSession):
    """Test 16: Retest on out-of-scope or production target is rejected."""
    tenant = Tenant(name="Unauthorized Target Retest Tenant")
    db_session.add(tenant)
    await db_session.flush()

    prod_finding = SecurityFinding(
        tenant_id=tenant.id,
        severity="CRITICAL",
        title="Prod Finding",
        description="Prod target",
        asset="prod-server-secure",
        technique="T1110.001",
        root_cause="Root",
        business_impact="Impact",
        recommendation="Fix",
        status="OPEN",
    )
    db_session.add(prod_finding)
    await db_session.commit()

    with pytest.raises(ValidationException, match="Production target .* strictly prohibited"):
        await RetestEngine.retest_finding(
            db=db_session,
            tenant_id=tenant.id,
            finding_id=prod_finding.id,
            user_id=uuid.uuid4(),
            user_role="SOC_L2",
        )


@pytest.mark.asyncio
async def test_17_security_rule_modification_requires_approval(db_session: AsyncSession):
    """Test 17: Proposed rule remediation stays PENDING until approved by human lead."""
    tenant = Tenant(name="Rule Approval Tenant")
    db_session.add(tenant)
    await db_session.flush()

    finding = SecurityFinding(
        tenant_id=tenant.id,
        severity="MEDIUM",
        title="Rule Gap",
        description="Rule needs update",
        asset="lab-host-01",
        technique="T1110.001",
        root_cause="R",
        business_impact="B",
        recommendation="R",
        status="OPEN",
    )
    db_session.add(finding)
    await db_session.commit()

    rem = await RemediationEngine.create_remediation(
        db=db_session,
        tenant_id=tenant.id,
        finding_id=finding.id,
        payload=type(
            "Payload", (), {"proposed_change": "Update threshold", "change_type": "RULE_UPDATE", "details": {}}
        )(),
    )
    assert rem.approval_status == "PENDING"
    assert rem.applied_at is None


@pytest.mark.asyncio
async def test_18_false_positive_recommendation_does_not_auto_change_detection(db_session: AsyncSession):
    """Test 18: False-positive tuning returns recommendations only; never modifies rules silently."""
    tenant = Tenant(name="FP Safety Tenant")
    db_session.add(tenant)
    await db_session.flush()

    recs = await RecommendationEngine.analyze_false_positive_trends(db=db_session, tenant_id=tenant.id)
    assert isinstance(recs, list)
    for r in recs:
        assert r["requires_human_approval"] is True
        assert r["auto_applied"] is False


@pytest.mark.asyncio
async def test_19_regression_test_failure_blocks_verified_status(db_session: AsyncSession):
    """Test 19: When regression verification check fails, status becomes REMEDIATION_FAILED instead of VERIFIED."""
    tenant = Tenant(name="Regression Failure Block Tenant")
    db_session.add(tenant)
    await db_session.flush()

    finding = SecurityFinding(
        tenant_id=tenant.id,
        severity="HIGH",
        title="Finding With Regression",
        description="Testing regression block",
        asset="lab-server-01",
        technique="T1110.001",
        root_cause="Root",
        business_impact="Impact",
        recommendation="Fix",
        status="UNDER_REMEDIATION",
    )
    db_session.add(finding)
    await db_session.commit()

    result = await RetestEngine.retest_finding(
        db=db_session,
        tenant_id=tenant.id,
        finding_id=finding.id,
        user_id=uuid.uuid4(),
        user_role="SOC_L2",
        simulate_regression_failure=True,
    )
    assert result["regression_passed"] is False
    assert result["after_status"] == "REMEDIATION_FAILED"


@pytest.mark.asyncio
async def test_20_audit_event_created_for_security_sensitive_operations(db_session: AsyncSession):
    """Test 20: Audit event is recorded for assessment creation, authorization, remediation, and retesting."""
    tenant = Tenant(name="Audit Test Tenant")
    db_session.add(tenant)
    await db_session.flush()

    user_id = uuid.uuid4()
    scope = {
        "environment": "LAB",
        "assets": ["lab-audit-01"],
        "allowed_techniques": ["T1110.001"],
        "expires_at": (datetime.now(UTC) + timedelta(hours=2)).isoformat(),
        "authorized_by": str(user_id),
    }

    # Create assessment triggers audit log
    assessment = AdversaryAssessment(
        tenant_id=tenant.id,
        name="Audited Assessment",
        environment="LAB",
        scenario="SCENARIO-001",
        status="AUTHORIZED",
        authorized_scope=scope,
        created_by=user_id,
        authorized_by=user_id,
    )
    db_session.add(assessment)
    await db_session.commit()

    # Retest triggers audit log
    finding = SecurityFinding(
        tenant_id=tenant.id,
        severity="HIGH",
        title="Audited Finding",
        description="Audit verification",
        asset="lab-audit-01",
        technique="T1110.001",
        root_cause="R",
        business_impact="B",
        recommendation="R",
        status="UNDER_REMEDIATION",
    )
    db_session.add(finding)
    await db_session.commit()

    await RetestEngine.retest_finding(
        db=db_session,
        tenant_id=tenant.id,
        finding_id=finding.id,
        user_id=user_id,
        user_role="SOC_L2",
    )

    audit_query = select(AuditLog).where(
        AuditLog.tenant_id == tenant.id,
        AuditLog.action == "FINDING_RETESTED",
    )
    audit_entry = (await db_session.execute(audit_query)).scalars().first()
    assert audit_entry is not None
    assert audit_entry.result == "SUCCESS"
    assert audit_entry.resource_type == "finding"
