"""Adversary Validation (AegisRed) API router."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.adversary.schemas import (
    AdversaryAssessmentAuthorize,
    AdversaryAssessmentCreate,
    AdversaryAssessmentRead,
    AssessmentResultRead,
)
from app.adversary.service import AdversaryService
from app.api.deps import get_db, get_tenant_context, require_roles
from app.core.exceptions import ForbiddenException, NotFoundException, ValidationException
from app.security.roles import Role
from app.security.tenant import TenantContext
from app.security_improvement.gap_engine import GapEngine

router = APIRouter(prefix="/adversary", tags=["Adversary Validation"])


@router.post(
    "/assessments",
    response_model=AdversaryAssessmentRead,
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
async def create_assessment_endpoint(
    payload: AdversaryAssessmentCreate,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Creates a new adversary validation assessment in DRAFT status."""
    try:
        assessment = await AdversaryService.create_assessment(
            db=db,
            tenant_id=ctx.tenant_id,
            user_id=ctx.user_id,
            payload=payload,
        )
        return assessment
    except ValidationException as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.get(
    "/assessments",
    response_model=list[AdversaryAssessmentRead],
    status_code=status.HTTP_200_OK,
)
async def list_assessments_endpoint(
    status_filter: str | None = Query(None, alias="status"),
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Lists adversary validation assessments for the tenant."""
    return await AdversaryService.list_assessments(
        db=db,
        tenant_id=ctx.tenant_id,
        status_filter=status_filter,
    )


@router.get(
    "/assessments/{assessment_id}",
    response_model=AdversaryAssessmentRead,
    status_code=status.HTTP_200_OK,
)
async def get_assessment_endpoint(
    assessment_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves an adversary assessment by ID."""
    try:
        assessment = await AdversaryService.get_assessment(
            db=db,
            tenant_id=ctx.tenant_id,
            assessment_id=assessment_id,
        )
        if not assessment:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment not found.")
        return assessment
    except NotFoundException as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.post(
    "/assessments/{assessment_id}/authorize",
    response_model=AdversaryAssessmentRead,
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
async def authorize_assessment_endpoint(
    assessment_id: uuid.UUID,
    payload: AdversaryAssessmentAuthorize | None = None,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Authorizes an assessment scope. Rejects AI authorizers and enforces LAB environment."""
    user_role = ctx.role or "SOC_L2"
    scope_dict = payload.authorized_scope.model_dump(mode="json") if (payload and payload.authorized_scope) else None
    try:
        return await AdversaryService.authorize_assessment(
            db=db,
            tenant_id=ctx.tenant_id,
            assessment_id=assessment_id,
            user_id=ctx.user_id,
            user_role=user_role,
            scope_update=scope_dict,
            is_ai_agent=False,
        )
    except ForbiddenException as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except (ValidationException, ValueError) as exc:
        if "not found" in str(exc).lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except NotFoundException as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.post(
    "/assessments/{assessment_id}/start",
    response_model=AssessmentResultRead,
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
async def start_assessment_endpoint(
    assessment_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Starts authorized adversary validation simulation, runs validation pipeline, and records gaps."""
    user_role = ctx.role or "SOC_L2"
    try:
        result = await AdversaryService.start_assessment(
            db=db,
            tenant_id=ctx.tenant_id,
            assessment_id=assessment_id,
            user_id=ctx.user_id,
            user_role=user_role,
            is_ai_agent=False,
        )
        # Automatically generate security findings for any detection gaps
        await GapEngine.create_findings_from_result(
            db=db,
            tenant_id=ctx.tenant_id,
            result=result,
        )
        return result
    except ForbiddenException as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except (ValidationException, ValueError) as exc:
        if "not found" in str(exc).lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except NotFoundException as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.post(
    "/assessments/{assessment_id}/cancel",
    response_model=AdversaryAssessmentRead,
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
async def cancel_assessment_endpoint(
    assessment_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Cancels a running or authorized assessment."""
    try:
        return await AdversaryService.cancel_assessment(
            db=db,
            tenant_id=ctx.tenant_id,
            assessment_id=assessment_id,
            user_id=ctx.user_id,
        )
    except ValidationException as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except NotFoundException as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.get(
    "/assessments/{assessment_id}/results",
    response_model=list[AssessmentResultRead],
    status_code=status.HTTP_200_OK,
)
async def get_assessment_results_endpoint(
    assessment_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """Retrieves all validation results for an assessment."""
    try:
        return await AdversaryService.get_assessment_results(
            db=db,
            tenant_id=ctx.tenant_id,
            assessment_id=assessment_id,
        )
    except NotFoundException as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
