"""Remediation tracking and human approval engine."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ForbiddenException, NotFoundException, ValidationException
from app.security_improvement.models import RemediationAction, SecurityFinding
from app.security_improvement.schemas import RemediationActionCreate
from app.services.audit_service import log_audit_event


class RemediationEngine:
    """Manages the creation, human approval, and application of remediation actions.

    SAFETY CONTROLS:
    1. AI cannot approve remediations.
    2. Modifying detection or security rules requires human approval (SOC_L2_LEAD or SOC_ADMIN).
    3. Applying a remediation transitions the finding to 'UNDER_REMEDIATION' pending retest.
    """

    @staticmethod
    async def create_remediation(
        db: AsyncSession,
        tenant_id: uuid.UUID,
        finding_id: uuid.UUID,
        payload: RemediationActionCreate,
    ) -> RemediationAction:
        """Create a pending remediation action for a security finding."""
        query = select(SecurityFinding).where(
            SecurityFinding.id == finding_id,
            SecurityFinding.tenant_id == tenant_id,
        )
        finding = (await db.execute(query)).scalars().first()
        if not finding:
            raise NotFoundException(f"Security finding {finding_id} not found.")

        remediation = RemediationAction(
            tenant_id=tenant_id,
            finding_id=finding_id,
            proposed_change=payload.proposed_change,
            change_type=payload.change_type,
            approval_status="PENDING",
            details=payload.details,
        )
        db.add(remediation)
        finding.status = "UNDER_REMEDIATION"
        finding.updated_at = datetime.now(UTC)

        await db.commit()
        await db.refresh(remediation)

        await log_audit_event(
            db=db,
            tenant_id=tenant_id,
            action="REMEDIATION_PROPOSED",
            resource_type="finding",
            resource_id=str(finding_id),
            result="SUCCESS",
            user_id=None,
            metadata={
                "remediation_id": str(remediation.id),
                "change_type": payload.change_type,
            },
        )
        return remediation

    @staticmethod
    async def approve_remediation(
        db: AsyncSession,
        tenant_id: uuid.UUID,
        remediation_id: uuid.UUID,
        approver_id: uuid.UUID,
        user_role: str,
        is_ai_agent: bool = False,
    ) -> RemediationAction:
        """Human approval for a proposed remediation.

        Rejects AI agent approvers and requires SOC_L2_LEAD or SOC_ADMIN.
        """
        if is_ai_agent:
            raise ForbiddenException("AI agents are strictly forbidden from approving remediation actions.")

        if user_role not in ("SOC_L2_LEAD", "SOC_ADMIN"):
            raise ForbiddenException("Only SOC_L2_LEAD or SOC_ADMIN may approve remediation actions.")

        query = select(RemediationAction).where(
            RemediationAction.id == remediation_id,
            RemediationAction.tenant_id == tenant_id,
        )
        remediation = (await db.execute(query)).scalars().first()
        if not remediation:
            raise NotFoundException(f"Remediation action {remediation_id} not found.")

        if remediation.approval_status != "PENDING":
            raise ValidationException(f"Remediation already has status {remediation.approval_status}.")

        remediation.approval_status = "APPROVED"
        remediation.approved_by = approver_id
        remediation.applied_at = datetime.now(UTC)

        await db.commit()
        await db.refresh(remediation)

        await log_audit_event(
            db=db,
            tenant_id=tenant_id,
            action="REMEDIATION_APPROVED",
            resource_type="remediation",
            resource_id=str(remediation.id),
            result="SUCCESS",
            user_id=approver_id,
            metadata={
                "finding_id": str(remediation.finding_id),
                "approved_by": str(approver_id),
            },
        )
        return remediation
