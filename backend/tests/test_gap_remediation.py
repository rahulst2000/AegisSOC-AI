import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.adversary.models import AssessmentResult
from app.core.exceptions import ForbiddenException, ValidationException
from app.models.tenant import Tenant
from app.security_improvement.gap_engine import GapEngine
from app.security_improvement.models import SecurityFinding
from app.security_improvement.remediation import RemediationEngine
from app.security_improvement.retest import RetestEngine
from app.security_improvement.schemas import RemediationActionCreate


@pytest.mark.asyncio
async def test_gap_detection_from_failed_detection(db_session: AsyncSession):
    """
    Verifies that when a simulation succeeds but detection fails,
    GapEngine correctly detects DETECTION_GAP with HIGH severity and creates a SecurityFinding.
    """
    tenant = Tenant(name="Gap Test Tenant")
    db_session.add(tenant)
    await db_session.flush()

    assessment_id = uuid.uuid4()
    failed_result = AssessmentResult(
        tenant_id=tenant.id,
        assessment_id=assessment_id,
        scenario_id="SCENARIO-001",
        technique_id="T1110.001",
        target="lab-unmonitored-host",
        simulation_status="PASS",
        detection_status="FAIL",
        correlation_status="NOT_TESTED",
        investigation_status="NOT_TESTED",
        response_status="NOT_TESTED",
        verification_status="NOT_TESTED",
        cleanup_status="CLEANED",
        overall_result="FAIL",
    )
    db_session.add(failed_result)
    await db_session.commit()

    gaps = GapEngine.analyze_result(failed_result)
    assert len(gaps) == 1
    assert gaps[0].gap_type == "DETECTION_GAP"
    assert gaps[0].severity == "HIGH"
    assert gaps[0].technique_id == "T1110.001"

    findings = await GapEngine.create_findings_from_result(
        db=db_session,
        tenant_id=tenant.id,
        result=failed_result,
    )
    assert len(findings) == 1
    assert findings[0].status == "OPEN"
    assert findings[0].asset == "lab-unmonitored-host"
    assert findings[0].technique == "T1110.001"


@pytest.mark.asyncio
async def test_remediation_lifecycle_and_human_approval(db_session: AsyncSession):
    """
    Verifies finding -> proposal -> human approval -> applied transition.
    Enforces that AI agents cannot approve remediations.
    """
    tenant = Tenant(name="Remediation Tenant")
    db_session.add(tenant)
    await db_session.flush()

    user_id = uuid.uuid4()
    finding = SecurityFinding(
        tenant_id=tenant.id,
        severity="HIGH",
        title="DETECTION_GAP: T1110.001 on lab-host-01",
        description="SSH brute force detection missing",
        asset="lab-host-01",
        technique="T1110.001",
        root_cause="Missing rule threshold",
        business_impact="Brute force undetected",
        recommendation="Tune SSH threshold rule",
        status="OPEN",
    )
    db_session.add(finding)
    await db_session.commit()

    # 1. Propose Remediation
    payload = RemediationActionCreate(
        proposed_change="Deploy SIGMA-SSH-BRUTEFORCE rule to lab-host-01",
        change_type="RULE_UPDATE",
    )
    remediation = await RemediationEngine.create_remediation(
        db=db_session,
        tenant_id=tenant.id,
        finding_id=finding.id,
        payload=payload,
    )
    assert remediation.approval_status == "PENDING"
    assert finding.status == "UNDER_REMEDIATION"

    # 2. AI approval attempt must be blocked
    with pytest.raises(ForbiddenException, match="AI agents are strictly forbidden"):
        await RemediationEngine.approve_remediation(
            db=db_session,
            tenant_id=tenant.id,
            remediation_id=remediation.id,
            approver_id=user_id,
            user_role="SOC_L2",
            is_ai_agent=True,
        )

    # 3. Human Approval Succeeds
    approved = await RemediationEngine.approve_remediation(
        db=db_session,
        tenant_id=tenant.id,
        remediation_id=remediation.id,
        approver_id=user_id,
        user_role="SOC_L2_LEAD",
        is_ai_agent=False,
    )
    assert approved.approval_status == "APPROVED"
    assert approved.applied_at is not None


@pytest.mark.asyncio
async def test_retest_finding_success_to_verified(db_session: AsyncSession):
    """
    Verifies that retesting an authorized lab finding produces PASS evidence,
    passes regression protection, and updates status to VERIFIED.
    """
    tenant = Tenant(name="Retest Tenant")
    db_session.add(tenant)
    await db_session.flush()

    user_id = uuid.uuid4()
    finding = SecurityFinding(
        tenant_id=tenant.id,
        severity="HIGH",
        title="DETECTION_GAP: T1110.001 on lab-server-01",
        description="SSH brute force gap to be verified",
        asset="lab-server-01",
        technique="T1110.001",
        root_cause="Rule was disabled",
        business_impact="Potential lateral movement",
        recommendation="Enable rule",
        status="UNDER_REMEDIATION",
    )
    db_session.add(finding)
    await db_session.commit()

    retest_result = await RetestEngine.retest_finding(
        db=db_session,
        tenant_id=tenant.id,
        finding_id=finding.id,
        user_id=user_id,
        user_role="SOC_L2",
    )

    assert retest_result["before_status"] == "UNDER_REMEDIATION"
    assert retest_result["after_status"] == "VERIFIED"
    assert retest_result["detection_status"] == "PASS"
    assert retest_result["regression_passed"] is True
    assert retest_result["evidence_count"] > 0

    await db_session.refresh(finding)
    assert finding.status == "VERIFIED"
    assert len(finding.evidence_ids) > 0


@pytest.mark.asyncio
async def test_retest_regression_failure_blocks_verified(db_session: AsyncSession):
    """
    Requirement 14 & 19: Regression test failure blocks VERIFIED status.
    """
    tenant = Tenant(name="Regression Failure Tenant")
    db_session.add(tenant)
    await db_session.flush()

    user_id = uuid.uuid4()
    finding = SecurityFinding(
        tenant_id=tenant.id,
        severity="HIGH",
        title="DETECTION_GAP: T1110.001 on lab-server-01",
        description="SSH brute force gap",
        asset="lab-server-01",
        technique="T1110.001",
        root_cause="Rule was disabled",
        business_impact="None",
        recommendation="Enable rule",
        status="UNDER_REMEDIATION",
    )
    db_session.add(finding)
    await db_session.commit()

    retest_result = await RetestEngine.retest_finding(
        db=db_session,
        tenant_id=tenant.id,
        finding_id=finding.id,
        user_id=user_id,
        user_role="SOC_L2",
        simulate_regression_failure=True,
    )

    # Even if detection passes, regression failure blocks VERIFIED
    assert retest_result["regression_passed"] is False
    assert retest_result["after_status"] == "REMEDIATION_FAILED"

    await db_session.refresh(finding)
    assert finding.status == "REMEDIATION_FAILED"


@pytest.mark.asyncio
async def test_retest_production_target_rejected(db_session: AsyncSession):
    """
    Requirement 16: Retest cannot access unauthorized or production targets.
    """
    tenant = Tenant(name="Prod Retest Block Tenant")
    db_session.add(tenant)
    await db_session.flush()

    user_id = uuid.uuid4()
    prod_finding = SecurityFinding(
        tenant_id=tenant.id,
        severity="CRITICAL",
        title="Production Finding",
        description="Production host finding",
        asset="prod-database-cluster-01",
        technique="T1110.001",
        root_cause="Production issue",
        business_impact="Critical",
        recommendation="Fix config",
        status="OPEN",
    )
    db_session.add(prod_finding)
    await db_session.commit()

    with pytest.raises(ValidationException, match="Production target .* strictly prohibited"):
        await RetestEngine.retest_finding(
            db=db_session,
            tenant_id=tenant.id,
            finding_id=prod_finding.id,
            user_id=user_id,
            user_role="SOC_L2",
        )
