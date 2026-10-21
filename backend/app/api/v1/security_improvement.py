"""Security Improvement, Findings, Remediation, and Retesting API router."""

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_tenant_context, require_roles
from app.core.exceptions import ForbiddenException, NotFoundException, ValidationException
from app.security.roles import Role
from app.security.tenant import TenantContext
from app.security_improvement.schemas import (
    DetectionGapReport,
    MitreCoverageItem,
    RemediationActionCreate,
    RemediationActionRead,
    SecurityFindingCreate,
    SecurityFindingRead,
    SecurityPostureReport,
)
from app.security_improvement.service import SecurityImprovementService

router = APIRouter(prefix="/security-improvement", tags=["Security Improvement"])


@router.get(
    "/gaps",
    response_model=list[DetectionGapReport],
    status_code=status.HTTP_200_OK,
)
async def list_gaps_endpoint(
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Identifies all detection, correlation, investigation, response, and verification gaps."""
    return await SecurityImprovementService.get_gaps(db=db, tenant_id=ctx.tenant_id)


@router.get(
    "/coverage",
    response_model=list[MitreCoverageItem],
    status_code=status.HTTP_200_OK,
)
async def get_coverage_endpoint(
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Returns actual ATT&CK adversary validation and detection coverage matrix."""
    return await SecurityImprovementService.get_coverage_matrix(db=db, tenant_id=ctx.tenant_id)


@router.get(
    "/posture",
    response_model=SecurityPostureReport,
    status_code=status.HTTP_200_OK,
)
async def get_posture_endpoint(
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Returns evidence-backed security posture report across operational categories."""
    return await SecurityImprovementService.get_posture_report(db=db, tenant_id=ctx.tenant_id)


@router.get(
    "/recommendations",
    response_model=list[dict[str, Any]],
    status_code=status.HTTP_200_OK,
)
async def get_recommendations_endpoint(
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Returns false-positive and rule tuning recommendations requiring human approval."""
    return await SecurityImprovementService.get_recommendations(db=db, tenant_id=ctx.tenant_id)


@router.get(
    "/findings",
    response_model=list[SecurityFindingRead],
    status_code=status.HTTP_200_OK,
)
async def list_findings_endpoint(
    status_filter: str | None = Query(None, alias="status"),
    severity: str | None = Query(None),
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Lists security findings for the tenant."""
    return await SecurityImprovementService.list_findings(
        db=db,
        tenant_id=ctx.tenant_id,
        status=status_filter,
        severity=severity,
    )


@router.get(
    "/findings/{finding_id}",
    response_model=SecurityFindingRead,
    status_code=status.HTTP_200_OK,
)
async def get_finding_endpoint(
    finding_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves a single finding with associated remediations."""
    try:
        return await SecurityImprovementService.get_finding(
            db=db,
            tenant_id=ctx.tenant_id,
            finding_id=finding_id,
        )
    except NotFoundException as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.post(
    "/findings",
    response_model=SecurityFindingRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(
            require_roles(
                [
                    Role.TENANT_ADMIN,
                    Role.SOC_L2,
                    Role.SECURITY_ENGINEER,
                    Role.SECURITY_MANAGER,
                    Role.CISO,
                ]
            )
        )
    ],
)
async def create_finding_endpoint(
    payload: SecurityFindingCreate,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Manually creates a security finding."""
    return await SecurityImprovementService.create_finding(
        db=db,
        tenant_id=ctx.tenant_id,
        payload=payload,
    )


@router.post(
    "/findings/{finding_id}/remediate",
    response_model=RemediationActionRead,
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
async def remediate_finding_endpoint(
    finding_id: uuid.UUID,
    payload: RemediationActionCreate,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Proposes a remediation action for a finding. Requires subsequent approval to apply."""
    try:
        return await SecurityImprovementService.create_remediation(
            db=db,
            tenant_id=ctx.tenant_id,
            finding_id=finding_id,
            payload=payload,
        )
    except NotFoundException as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.post(
    "/remediations/{remediation_id}/approve",
    response_model=RemediationActionRead,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(
            require_roles(
                [
                    Role.TENANT_ADMIN,
                    Role.SOC_L2,
                    Role.SECURITY_ENGINEER,
                    Role.SECURITY_MANAGER,
                    Role.CISO,
                ]
            )
        )
    ],
)
async def approve_remediation_endpoint(
    remediation_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Approves and applies a proposed remediation. Human-only operation."""
    user_role = ctx.role or "SOC_L2"
    try:
        return await SecurityImprovementService.approve_remediation(
            db=db,
            tenant_id=ctx.tenant_id,
            remediation_id=remediation_id,
            approver_id=ctx.user_id,
            user_role=user_role,
            is_ai_agent=False,
        )
    except ForbiddenException as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ValidationException as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except NotFoundException as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.post(
    "/findings/{finding_id}/retest",
    response_model=dict[str, Any],
    status_code=status.HTTP_200_OK,
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
async def retest_finding_endpoint(
    finding_id: uuid.UUID,
    simulate_regression_failure: bool = Query(False),
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Triggers an authorized retest of a remediated finding with regression protection."""
    user_role = ctx.role or "SOC_L2"
    try:
        return await SecurityImprovementService.retest_finding(
            db=db,
            tenant_id=ctx.tenant_id,
            finding_id=finding_id,
            user_id=ctx.user_id,
            user_role=user_role,
            is_ai_agent=False,
            simulate_regression_failure=simulate_regression_failure,
        )
    except ForbiddenException as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except ValidationException as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except NotFoundException as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
