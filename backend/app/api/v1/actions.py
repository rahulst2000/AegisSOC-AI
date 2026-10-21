import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_tenant_context, require_roles
from app.playbooks.executor import (
    approve_action_request,
    create_action_request,
    execute_approved_action,
    reject_action_request,
)
from app.playbooks.models import ActionRequest
from app.playbooks.schemas import (
    ActionApprovalRequest,
    ActionRejectionRequest,
    ActionRequestCreate,
    ActionRequestRead,
    VerificationResultRead,
)
from app.security.roles import Role
from app.security.tenant import TenantContext

router = APIRouter(prefix="/actions", tags=["Playbook Actions"])


@router.post(
    "",
    response_model=ActionRequestRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(
            require_roles(
                [
                    Role.TENANT_ADMIN,
                    Role.SOC_L1,
                    Role.SOC_L2,
                    Role.SECURITY_ENGINEER,
                    Role.SECURITY_MANAGER,
                    Role.CISO,
                ]
            )
        )
    ],
)
async def create_action_endpoint(
    payload: ActionRequestCreate,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Creates a new security action request under policy control."""
    try:
        return await create_action_request(
            db=db,
            tenant_id=ctx.tenant_id,
            incident_id=payload.incident_id,
            action_type=payload.action_type,
            target_entity=payload.target_entity,
            target_type=payload.target_type,
            playbook_id=payload.playbook_id,
            requested_by=ctx.user_id,
            investigation_id=payload.investigation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.get(
    "",
    response_model=list[ActionRequestRead],
    status_code=status.HTTP_200_OK,
)
async def list_actions_endpoint(
    incident_id: uuid.UUID | None = Query(None),
    approval_status: str | None = Query(None),
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Lists action requests for the tenant, optionally filtered by incident."""
    stmt = select(ActionRequest).where(ActionRequest.tenant_id == ctx.tenant_id)
    if incident_id:
        stmt = stmt.where(ActionRequest.incident_id == incident_id)
    if approval_status:
        stmt = stmt.where(ActionRequest.approval_status == approval_status.upper())
    stmt = stmt.order_by(ActionRequest.requested_at.desc())
    res = await db.execute(stmt)
    return list(res.scalars().all())


@router.get(
    "/{action_id}",
    response_model=ActionRequestRead,
    status_code=status.HTTP_200_OK,
)
async def get_action_endpoint(
    action_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves an action request by ID."""
    stmt = select(ActionRequest).where(
        ActionRequest.id == action_id,
        ActionRequest.tenant_id == ctx.tenant_id,
    )
    res = await db.execute(stmt)
    action = res.scalars().first()
    if not action:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Action not found.")
    return action


@router.post(
    "/{action_id}/approve",
    response_model=ActionRequestRead,
    status_code=status.HTTP_200_OK,
)
async def approve_action_endpoint(
    action_id: uuid.UUID,
    payload: ActionApprovalRequest | None = None,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Approves an action request. Enforces role authorization and human approval."""
    user_role = ctx.roles[0] if ctx.roles else "SOC_L1_ANALYST"
    reason = payload.reason if payload else None
    try:
        return await approve_action_request(
            db=db,
            tenant_id=ctx.tenant_id,
            action_id=action_id,
            user_id=ctx.user_id,
            user_role=user_role,
            reason=reason,
        )
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post(
    "/{action_id}/reject",
    response_model=ActionRequestRead,
    status_code=status.HTTP_200_OK,
)
async def reject_action_endpoint(
    action_id: uuid.UUID,
    payload: ActionRejectionRequest,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Rejects an action request with mandatory justification."""
    user_role = ctx.roles[0] if ctx.roles else "SOC_L1_ANALYST"
    try:
        return await reject_action_request(
            db=db,
            tenant_id=ctx.tenant_id,
            action_id=action_id,
            user_id=ctx.user_id,
            user_role=user_role,
            reason=payload.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post(
    "/{action_id}/execute",
    response_model=ActionRequestRead,
    status_code=status.HTTP_200_OK,
)
async def execute_action_endpoint(
    action_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Executes an action request that has passed approval. Invokes adapter and runs verification."""
    try:
        return await execute_approved_action(
            db=db,
            tenant_id=ctx.tenant_id,
            action_id=action_id,
            user_id=ctx.user_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.get(
    "/{action_id}/verification",
    response_model=VerificationResultRead,
    status_code=status.HTTP_200_OK,
)
async def get_action_verification_endpoint(
    action_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves verification details (state before vs after) for an action."""
    stmt = select(ActionRequest).where(
        ActionRequest.id == action_id,
        ActionRequest.tenant_id == ctx.tenant_id,
    )
    res = await db.execute(stmt)
    action = res.scalars().first()
    if not action:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Action not found.")

    return VerificationResultRead(
        action_id=action.id,
        verification_status=action.verification_status,
        details=action.error or f"Action status: {action.execution_status}",
        before_state=action.evidence_before,
        after_state=action.evidence_after,
        verified_at=action.timestamp,
    )
