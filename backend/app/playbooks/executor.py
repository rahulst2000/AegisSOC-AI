import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert
from app.playbooks.actions import MockEndpointAdapter, MockFirewallAdapter, MockIdentityAdapter
from app.playbooks.models import ActionRequest
from app.playbooks.validator import check_role_authorization, validate_action_request
from app.playbooks.verification import verify_response_action
from app.services.audit_service import log_audit_event


async def create_action_request(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    incident_id: uuid.UUID,
    action_type: str,
    target_entity: str,
    target_type: str,
    playbook_id: str,
    requested_by: uuid.UUID | None = None,
    investigation_id: uuid.UUID | None = None,
) -> ActionRequest:
    """Creates a new action request following policy validation."""
    val_res = await validate_action_request(
        db=db,
        tenant_id=tenant_id,
        incident_id=incident_id,
        action_type=action_type,
        target_entity=target_entity,
        target_type=target_type,
    )
    if not val_res.valid:
        raise ValueError(val_res.error or "Action validation failed")

    decision = val_res.policy_decision
    policy_dict = decision.model_dump() if decision else {}

    action = ActionRequest(
        incident_id=incident_id,
        investigation_id=investigation_id,
        tenant_id=tenant_id,
        action_type=action_type.strip().upper(),
        target_entity=target_entity.strip(),
        target_type=target_type.strip().upper(),
        playbook_id=playbook_id.strip().upper(),
        requested_by=requested_by,
        requested_at=datetime.now(UTC),
        policy_evaluation=policy_dict,
        required_approval_role=decision.required_approval_role if decision else "SOC_L1_ANALYST",
        approval_status="REQUESTED",
        execution_status="PENDING",
        verification_status="PENDING",
        evidence_before={},
        evidence_after={},
        result={},
    )
    db.add(action)
    await db.flush()

    await log_audit_event(
        db=db,
        tenant_id=tenant_id,
        user_id=requested_by,
        action="ACTION_REQUESTED",
        resource_type="action_request",
        resource_id=str(action.id),
        result="SUCCESS",
        metadata={
            "incident_id": str(incident_id),
            "action_type": action.action_type,
            "target": action.target_entity,
            "required_role": action.required_approval_role,
        },
    )
    return action


async def approve_action_request(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    action_id: uuid.UUID,
    user_id: uuid.UUID,
    user_role: str,
    reason: str | None = None,
) -> ActionRequest:
    """Approves an action request if user role meets policy requirement."""
    stmt = select(ActionRequest).where(
        ActionRequest.id == action_id,
        ActionRequest.tenant_id == tenant_id,
    )
    res = await db.execute(stmt)
    action = res.scalars().first()
    if not action:
        raise ValueError(f"Action request {action_id} not found for tenant {tenant_id}")

    if action.approval_status != "REQUESTED":
        raise ValueError(f"Action request {action_id} is in status '{action.approval_status}', cannot be approved.")

    # Check RBAC authorization
    if not check_role_authorization(user_role, action.required_approval_role):
        await log_audit_event(
            db=db,
            tenant_id=tenant_id,
            user_id=user_id,
            action="ACTION_APPROVAL_DENIED",
            resource_type="action_request",
            resource_id=str(action.id),
            result="DENIED",
            metadata={
                "user_role": user_role,
                "required_role": action.required_approval_role,
            },
        )
        raise PermissionError(
            f"User role '{user_role}' is insufficient to approve action requiring '{action.required_approval_role}'."
        )

    action.approval_status = "APPROVED"
    action.approved_by = user_id
    action.approved_at = datetime.now(UTC)
    await db.flush()

    await log_audit_event(
        db=db,
        tenant_id=tenant_id,
        user_id=user_id,
        action="ACTION_APPROVED",
        resource_type="action_request",
        resource_id=str(action.id),
        result="SUCCESS",
        metadata={
            "action_type": action.action_type,
            "target": action.target_entity,
            "approver_role": user_role,
            "reason": reason,
        },
    )
    return action


async def reject_action_request(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    action_id: uuid.UUID,
    user_id: uuid.UUID,
    user_role: str,
    reason: str,
) -> ActionRequest:
    """Rejects an action request."""
    stmt = select(ActionRequest).where(
        ActionRequest.id == action_id,
        ActionRequest.tenant_id == tenant_id,
    )
    res = await db.execute(stmt)
    action = res.scalars().first()
    if not action:
        raise ValueError(f"Action request {action_id} not found for tenant {tenant_id}")

    action.approval_status = "REJECTED"
    action.approved_by = user_id
    action.approved_at = datetime.now(UTC)
    action.rejection_reason = reason
    await db.flush()

    await log_audit_event(
        db=db,
        tenant_id=tenant_id,
        user_id=user_id,
        action="ACTION_REJECTED",
        resource_type="action_request",
        resource_id=str(action.id),
        result="SUCCESS",
        metadata={
            "action_type": action.action_type,
            "target": action.target_entity,
            "reason": reason,
        },
    )
    return action


async def execute_approved_action(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    action_id: uuid.UUID,
    user_id: uuid.UUID | None = None,
) -> ActionRequest:
    """
    Executes an action request that has passed human approval.
    Applies mock adapter, runs verification, and logs results.
    """
    stmt = select(ActionRequest).where(
        ActionRequest.id == action_id,
        ActionRequest.tenant_id == tenant_id,
    )
    res = await db.execute(stmt)
    action = res.scalars().first()
    if not action:
        raise ValueError(f"Action request {action_id} not found for tenant {tenant_id}")

    if action.approval_status != "APPROVED":
        raise ValueError(f"Action {action_id} must be APPROVED before execution (status={action.approval_status}).")

    action.execution_status = "EXECUTING"
    await db.flush()

    action_type = action.action_type.upper()
    target = action.target_entity

    # Dispatch to appropriate lab adapter
    adapter_output: dict[str, Any] = {}
    if action_type == "IP_CONTAINMENT":
        adapter_output = MockFirewallAdapter.block_ip(target)
    elif action_type == "ACCOUNT_LOCKOUT":
        adapter_output = MockIdentityAdapter.lock_account(target)
    elif action_type == "SESSION_REVOCATION":
        adapter_output = MockIdentityAdapter.revoke_sessions(target)
    elif action_type == "HOST_ISOLATION":
        adapter_output = MockEndpointAdapter.isolate_host(target)
    elif action_type in ("L2_ESCALATION", "COLLECT_EVIDENCE"):
        adapter_output = {
            "before": {"status": "OPEN"},
            "action": action_type,
            "after": {"status": "DISPATCHED"},
            "success": True,
        }
    else:
        adapter_output = {
            "before": {},
            "action": action_type,
            "after": {"error": f"Unknown action type: {action_type}"},
            "success": False,
        }

    before_state = adapter_output.get("before", {})
    after_state = adapter_output.get("after", {})
    adapter_success = adapter_output.get("success", False)

    action.evidence_before = before_state
    action.evidence_after = after_state
    action.result = adapter_output

    # Run Response Verification
    verification = verify_response_action(
        action_type=action_type,
        before_state=before_state,
        after_state=after_state,
        adapter_success=adapter_success,
    )

    action.verification_status = verification.status

    if verification.verified:
        action.execution_status = "SUCCEEDED"
        action.error = None
        await log_audit_event(
            db=db,
            tenant_id=tenant_id,
            user_id=user_id,
            action="ACTION_VERIFIED",
            resource_type="action_request",
            resource_id=str(action.id),
            result="SUCCESS",
            metadata={
                "action_type": action_type,
                "target": target,
                "details": verification.details,
            },
        )
    else:
        action.execution_status = "FAILED"
        action.error = verification.details
        await log_audit_event(
            db=db,
            tenant_id=tenant_id,
            user_id=user_id,
            action="ACTION_FAILED",
            resource_type="action_request",
            resource_id=str(action.id),
            result="FAILURE",
            metadata={
                "action_type": action_type,
                "target": target,
                "error": verification.details,
            },
        )

        # Generate alert for analyst review upon verification failure
        fail_alert = Alert(
            tenant_id=tenant_id,
            detection_rule=f"VERIFICATION_FAILED:{action_type}",
            severity="HIGH",
            confidence=1.0,
            status="OPEN",
        )
        db.add(fail_alert)

    await db.flush()
    return action
