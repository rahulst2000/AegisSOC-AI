import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_tenant_context, require_roles
from app.detection.models import DetectionResult
from app.detection.schemas import AnalystFeedbackUpdate, DetectionResultRead
from app.security.roles import Role
from app.security.tenant import TenantContext
from app.services.audit_service import log_audit_event

router = APIRouter(prefix="/detections", tags=["Detections"])


@router.get("", response_model=list[DetectionResultRead], status_code=status.HTTP_200_OK)
async def list_detections(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    severity: str | None = Query(None),
    rule_id: str | None = Query(None),
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """
    Lists evidence-backed detection results strictly bounded to the authenticated tenant.
    """
    stmt = (
        select(DetectionResult)
        .where(DetectionResult.tenant_id == ctx.tenant_id)
        .order_by(DetectionResult.timestamp.desc())
    )
    if severity:
        stmt = stmt.where(DetectionResult.severity == severity.upper())
    if rule_id:
        stmt = stmt.where(DetectionResult.rule_id == rule_id)

    stmt = stmt.offset(skip).limit(limit)
    res = await db.execute(stmt)
    return list(res.scalars().all())


@router.get("/{detection_id}", response_model=DetectionResultRead, status_code=status.HTTP_200_OK)
async def get_detection(
    detection_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieves a single detection result by ID.
    Enforces strict tenant boundary isolation.
    """
    stmt = select(DetectionResult).where(
        DetectionResult.id == detection_id,
        DetectionResult.tenant_id == ctx.tenant_id,
    )
    res = await db.execute(stmt)
    detection = res.scalars().first()
    if not detection:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection with ID '{detection_id}' not found.",
        )
    return detection


@router.patch(
    "/{detection_id}/feedback",
    response_model=DetectionResultRead,
    status_code=status.HTTP_200_OK,
    dependencies=[
        Depends(
            require_roles(
                [
                    Role.TENANT_ADMIN,
                    Role.SECURITY_ENGINEER,
                    Role.SOC_L1,
                    Role.SOC_L2,
                    Role.SECURITY_MANAGER,
                    Role.CISO,
                ]
            )
        )
    ],
)
async def submit_analyst_feedback(
    detection_id: uuid.UUID,
    feedback_in: AnalystFeedbackUpdate,
    ctx: TenantContext = Depends(get_tenant_context),
    db: AsyncSession = Depends(get_db),
):
    """
    Records false positive review and analyst feedback metadata for a detection result.
    Enforces strict tenant boundary isolation and audits operation.
    """
    stmt = select(DetectionResult).where(
        DetectionResult.id == detection_id,
        DetectionResult.tenant_id == ctx.tenant_id,
    )
    res = await db.execute(stmt)
    detection = res.scalars().first()
    if not detection:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection with ID '{detection_id}' not found.",
        )

    detection.false_positive_status = feedback_in.false_positive_status
    detection.analyst_feedback = feedback_in.analyst_feedback

    await log_audit_event(
        db=db,
        tenant_id=ctx.tenant_id,
        user_id=ctx.user_id,
        action="UPDATE_DETECTION_FEEDBACK",
        resource_type="DETECTION_RESULT",
        resource_id=str(detection.id),
        result="SUCCESS",
        metadata={
            "false_positive_status": feedback_in.false_positive_status,
            "rule_id": detection.rule_id,
        },
    )

    await db.commit()
    await db.refresh(detection)
    return detection
