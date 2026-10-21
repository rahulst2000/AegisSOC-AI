import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.escalation.service import escalate_incident, get_escalation_by_incident
from app.models.alert import Alert
from app.models.incident import Incident
from app.models.tenant import Tenant
from app.playbooks.executor import (
    approve_action_request,
    create_action_request,
    execute_approved_action,
)
from app.policy.models import SecurityPolicy


@pytest.mark.asyncio
async def test_scenario_g_l1_approves_mock_ip_containment_verified(
    db_session: AsyncSession,
):
    """
    Scenario G: L1 approves mock IP containment.
    Expected: Action executes successfully, verification confirms containment (VERIFIED).
    """
    tenant = Tenant(name="Playbook Tenant G")
    db_session.add(tenant)
    await db_session.flush()

    incident = Incident(
        tenant_id=tenant.id,
        title="Brute Force from 198.51.100.50",
        description="SSH attack in progress.",
        severity="HIGH",
        risk_score=80,
        confidence=0.90,
        status="OPEN",
        source_ips=["198.51.100.50"],
    )
    db_session.add(incident)
    await db_session.flush()

    user_id = uuid.uuid4()

    # 1. Create action request
    action = await create_action_request(
        db=db_session,
        tenant_id=tenant.id,
        incident_id=incident.id,
        action_type="IP_CONTAINMENT",
        target_entity="198.51.100.50",
        target_type="IP",
        playbook_id="PLAYBOOK-002",
        requested_by=user_id,
    )
    assert action.approval_status == "REQUESTED"
    assert action.execution_status == "PENDING"
    assert action.verification_status == "PENDING"

    # 2. Approve action with SOC_L1 role
    approved_action = await approve_action_request(
        db=db_session,
        tenant_id=tenant.id,
        action_id=action.id,
        user_id=user_id,
        user_role="SOC_L1_ANALYST",
        reason="Malicious source verified by forensic telemetry",
    )
    assert approved_action.approval_status == "APPROVED"

    # 3. Execute approved action
    executed = await execute_approved_action(
        db=db_session,
        tenant_id=tenant.id,
        action_id=action.id,
        user_id=user_id,
    )
    assert executed.execution_status == "SUCCEEDED"
    assert executed.verification_status == "VERIFIED"
    assert executed.evidence_before["traffic_status"] == "ALLOWED"
    assert executed.evidence_after["traffic_status"] == "DENIED"


@pytest.mark.asyncio
async def test_scenario_h_mock_response_failure_verification_failed_alert(
    db_session: AsyncSession,
):
    """
    Scenario H: Mock response fails.
    Expected: VERIFICATION_FAILED recorded, execution marked FAILED, alert generated for SOC review.
    """
    tenant = Tenant(name="Playbook Tenant H")
    db_session.add(tenant)
    await db_session.flush()

    incident = Incident(
        tenant_id=tenant.id,
        title="Unreachable Firewall Target",
        description="Simulated hardware firewall failure.",
        severity="HIGH",
        risk_score=80,
        confidence=0.90,
        status="OPEN",
    )
    db_session.add(incident)
    await db_session.flush()

    user_id = uuid.uuid4()

    # Target contains FAIL_SIMULATION trigger
    action = await create_action_request(
        db=db_session,
        tenant_id=tenant.id,
        incident_id=incident.id,
        action_type="IP_CONTAINMENT",
        target_entity="198.51.100.50_FAIL_SIMULATION",
        target_type="IP",
        playbook_id="PLAYBOOK-002",
        requested_by=user_id,
    )

    await approve_action_request(
        db=db_session,
        tenant_id=tenant.id,
        action_id=action.id,
        user_id=user_id,
        user_role="SOC_L1_ANALYST",
    )

    executed = await execute_approved_action(
        db=db_session,
        tenant_id=tenant.id,
        action_id=action.id,
        user_id=user_id,
    )
    assert executed.execution_status == "FAILED"
    assert executed.verification_status == "VERIFICATION_FAILED"
    assert "Perimeter firewall API connection timed out" in str(executed.error)

    # Verify that an Alert was created for analyst review
    stmt = select(Alert).where(Alert.tenant_id == tenant.id)
    res = await db_session.execute(stmt)
    alert = res.scalars().first()
    assert alert is not None
    assert "VERIFICATION_FAILED" in alert.detection_rule


@pytest.mark.asyncio
async def test_scenario_k_unauthorized_soc_l1_cannot_approve_l2_action(
    db_session: AsyncSession,
):
    """
    Scenario K: Unauthorized SOC L1 attempts to approve L2-only action (HOST_ISOLATION).
    Expected: PermissionError (HTTP 403 equivalent).
    """
    tenant = Tenant(name="Playbook Tenant K")
    db_session.add(tenant)
    await db_session.flush()

    incident = Incident(
        tenant_id=tenant.id,
        title="Host Isolation Incident",
        description="Candidate for host isolation.",
        severity="CRITICAL",
        risk_score=85,
        confidence=0.90,
        status="OPEN",
    )
    db_session.add(incident)
    await db_session.flush()

    user_id = uuid.uuid4()

    action = await create_action_request(
        db=db_session,
        tenant_id=tenant.id,
        incident_id=incident.id,
        action_type="HOST_ISOLATION",
        target_entity="finance-srv-01",
        target_type="HOST",
        playbook_id="PLAYBOOK-004",
        requested_by=user_id,
    )
    # HOST_ISOLATION requires SOC_L2_ANALYST per policy
    assert action.required_approval_role == "SOC_L2_ANALYST"

    # L1 approval attempt must be denied
    with pytest.raises(PermissionError) as exc_info:
        await approve_action_request(
            db=db_session,
            tenant_id=tenant.id,
            action_id=action.id,
            user_id=user_id,
            user_role="SOC_L1_ANALYST",
        )
    assert "insufficient to approve action requiring 'SOC_L2_ANALYST'" in str(exc_info.value)

    # L2 approval succeeds
    approved = await approve_action_request(
        db=db_session,
        tenant_id=tenant.id,
        action_id=action.id,
        user_id=user_id,
        user_role="SOC_L2_ANALYST",
    )
    assert approved.approval_status == "APPROVED"


@pytest.mark.asyncio
async def test_scenario_f_policy_layer_blocks_unauthorized_action(
    db_session: AsyncSession,
):
    """
    Scenario F: Policy layer blocks action when disabled by tenant policy or platform safety.
    """
    tenant = Tenant(name="Playbook Tenant F")
    db_session.add(tenant)
    await db_session.flush()

    # Disable IP_CONTAINMENT for this tenant
    policy = SecurityPolicy(
        tenant_id=tenant.id,
        name="Strict Lockdown - Containment Disabled",
        action_type="IP_CONTAINMENT",
        enabled=False,
        min_role_for_approval="DISABLED",
        require_human_approval=True,
    )
    db_session.add(policy)

    incident = Incident(
        tenant_id=tenant.id,
        title="Policy Block Test",
        description="Testing policy enforcement.",
        severity="HIGH",
        risk_score=75,
        confidence=0.80,
        status="OPEN",
    )
    db_session.add(incident)
    await db_session.flush()

    # Attempt to request IP_CONTAINMENT should be rejected
    with pytest.raises(ValueError) as exc_info:
        await create_action_request(
            db=db_session,
            tenant_id=tenant.id,
            incident_id=incident.id,
            action_type="IP_CONTAINMENT",
            target_entity="198.51.100.77",
            target_type="IP",
            playbook_id="PLAYBOOK-002",
        )
    assert "disabled by tenant policy" in str(exc_info.value)


@pytest.mark.asyncio
async def test_scenario_j_cross_tenant_action_operation_blocked(
    db_session: AsyncSession,
):
    """
    Scenario J: Tenant A action attempts to operate on Tenant B incident.
    Expected: ValueError / Not Found (cross-tenant isolation).
    """
    tenant_a = Tenant(name="Tenant Alpha")
    tenant_b = Tenant(name="Tenant Beta")
    db_session.add_all([tenant_a, tenant_b])
    await db_session.flush()

    incident_b = Incident(
        tenant_id=tenant_b.id,
        title="Tenant B Private Incident",
        description="Confidential incident belonging to Beta.",
        severity="HIGH",
        risk_score=80,
        confidence=0.90,
        status="OPEN",
    )
    db_session.add(incident_b)
    await db_session.flush()

    # Tenant A attempts to create an action request against Tenant B's incident
    with pytest.raises(ValueError) as exc_info:
        await create_action_request(
            db=db_session,
            tenant_id=tenant_a.id,
            incident_id=incident_b.id,
            action_type="IP_CONTAINMENT",
            target_entity="198.51.100.10",
            target_type="IP",
            playbook_id="PLAYBOOK-002",
        )
    assert "not found for tenant" in str(exc_info.value)


@pytest.mark.asyncio
async def test_scenario_l_critical_incident_l2_escalation_package_created(
    db_session: AsyncSession,
):
    """
    Scenario L: Critical incident escalates to Tier-2 SOC.
    Expected: L2 investigation package created with all forensic context, timeline, and actions.
    """
    tenant = Tenant(name="Playbook Tenant L")
    db_session.add(tenant)
    await db_session.flush()

    incident = Incident(
        tenant_id=tenant.id,
        title="Multi-Host Lateral Movement Campaign",
        description="Adversary compromised multiple domain controllers.",
        severity="CRITICAL",
        risk_score=95,
        confidence=0.98,
        status="OPEN",
        mitre_techniques=["T1078", "T1078.003"],
        affected_assets=["dc01.corp", "dc02.corp"],
        affected_users=["domain_admin"],
        source_ips=["198.51.100.200"],
    )
    db_session.add(incident)
    await db_session.flush()

    user_id = uuid.uuid4()

    # Escalate to L2
    escalation = await escalate_incident(
        db=db_session,
        tenant_id=tenant.id,
        incident_id=incident.id,
        reason="Multi-host domain compromise exceeding L1 remit",
        urgency="CRITICAL",
        user_id=user_id,
    )
    assert escalation.status == "OPEN"
    assert escalation.urgency == "CRITICAL"
    assert incident.status == "ESCALATED"

    # Inspect package
    pkg = escalation.l2_package
    assert pkg["incident_id"] == str(incident.id)
    assert pkg["why_escalated"] == "Multi-host domain compromise exceeding L1 remit"
    assert "dc01.corp" in pkg["affected_assets"]
    assert "domain_admin" in pkg["affected_users"]
    assert len(pkg["recommended_next_investigation"]) > 0

    # Retrieve from service
    fetched = await get_escalation_by_incident(db_session, tenant.id, incident.id)
    assert fetched is not None
    assert fetched.id == escalation.id
