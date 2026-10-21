import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.adversary.cleanup import execute_scenario_cleanup
from app.adversary.executor import execute_adversary_assessment
from app.adversary.models import AdversaryAssessment, AssessmentResult
from app.adversary.schemas import AdversaryAssessmentCreate, AuthorizedScope
from app.adversary.validator import check_adversary_authorization_role
from app.services.audit_service import log_audit_event


async def create_assessment(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    data: AdversaryAssessmentCreate | None = None,
    user_id: uuid.UUID | None = None,
    payload: AdversaryAssessmentCreate | None = None,
) -> AdversaryAssessment:
    """Creates a new adversary assessment in DRAFT status."""
    assessment_data = payload or data
    if not assessment_data:
        raise ValueError("Assessment data payload is required.")

    if assessment_data.authorized_scope.environment.upper() != "LAB":
        raise ValueError("Platform Safety Violation: Assessments can only be created for LAB environment.")

    assessment = AdversaryAssessment(
        tenant_id=tenant_id,
        name=assessment_data.name,
        description=assessment_data.description,
        environment=assessment_data.environment.upper(),
        authorized_scope=assessment_data.authorized_scope.model_dump(mode="json"),
        scenario=assessment_data.scenario,
        status="DRAFT",
        created_by=user_id,
    )
    db.add(assessment)
    await db.commit()
    await db.refresh(assessment)

    await log_audit_event(
        db=db,
        tenant_id=tenant_id,
        user_id=user_id,
        action="ADVERSARY_ASSESSMENT_CREATED",
        resource_type="adversary_assessment",
        resource_id=str(assessment.id),
        result="SUCCESS",
        metadata={"scenario": assessment_data.scenario, "environment": assessment_data.environment},
    )
    return assessment


async def authorize_assessment(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    assessment_id: uuid.UUID,
    user_id: uuid.UUID,
    user_role: str,
    scope_override: AuthorizedScope | dict[str, Any] | None = None,
    scope_update: AuthorizedScope | dict[str, Any] | None = None,
    is_ai_agent: bool = False,
) -> AdversaryAssessment:
    """Signs off on an assessment scope, advancing status from DRAFT to AUTHORIZED."""
    if is_ai_agent:
        raise ValueError("AI agents are strictly forbidden from authorizing assessments.")

    check_adversary_authorization_role(user_role)

    stmt = select(AdversaryAssessment).where(
        AdversaryAssessment.id == assessment_id,
        AdversaryAssessment.tenant_id == tenant_id,
    )
    res = await db.execute(stmt)
    assessment = res.scalars().first()
    if not assessment:
        raise ValueError(f"Adversary assessment {assessment_id} not found for tenant {tenant_id}")

    if assessment.status not in ("DRAFT", "CANCELLED"):
        raise ValueError(f"Cannot authorize assessment in '{assessment.status}' status.")

    scope_override = scope_override or scope_update
    scope_data = dict(assessment.authorized_scope or {})
    if scope_override:
        if isinstance(scope_override, dict):
            if scope_override.get("environment", "").upper() != "LAB":
                raise ValueError("Platform Safety Violation: Scope environment must be LAB.")
            scope_data.update(scope_override)
        else:
            if scope_override.environment.upper() != "LAB":
                raise ValueError("Platform Safety Violation: Scope environment must be LAB.")
            scope_data = scope_override.model_dump(mode="json")

    scope_data["authorized_by"] = str(user_id)
    assessment.authorized_scope = scope_data
    assessment.authorized_by = user_id
    assessment.status = "AUTHORIZED"

    await db.commit()
    await db.refresh(assessment)

    await log_audit_event(
        db=db,
        tenant_id=tenant_id,
        user_id=user_id,
        action="ADVERSARY_ASSESSMENT_AUTHORIZED",
        resource_type="adversary_assessment",
        resource_id=str(assessment.id),
        result="SUCCESS",
        metadata={"authorized_by": str(user_id)},
    )
    return assessment


async def start_assessment(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    assessment_id: uuid.UUID,
    user_id: uuid.UUID,
    user_role: str,
    is_ai_agent: bool = False,
) -> AssessmentResult:
    """Starts execution of an authorized adversary assessment."""
    if is_ai_agent:
        raise ValueError("AI agents are strictly forbidden from initiating adversary validation.")

    result = await execute_adversary_assessment(
        db=db,
        tenant_id=tenant_id,
        assessment_id=assessment_id,
        user_id=user_id,
        user_role=user_role,
    )

    # Automatically evaluate detection gaps and generate findings
    from app.security_improvement.gap_engine import evaluate_gaps_for_assessment

    await evaluate_gaps_for_assessment(db=db, tenant_id=tenant_id, result=result)

    return result


async def cancel_assessment(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    assessment_id: uuid.UUID,
    user_id: uuid.UUID,
) -> AdversaryAssessment:
    """Cancels a pending or running assessment and triggers cleanup."""
    stmt = select(AdversaryAssessment).where(
        AdversaryAssessment.id == assessment_id,
        AdversaryAssessment.tenant_id == tenant_id,
    )
    res = await db.execute(stmt)
    assessment = res.scalars().first()
    if not assessment:
        raise ValueError(f"Adversary assessment {assessment_id} not found for tenant {tenant_id}")

    if assessment.status in ("COMPLETED", "FAILED"):
        raise ValueError(f"Cannot cancel assessment in terminal status '{assessment.status}'.")

    was_running = assessment.status == "RUNNING"
    assessment.status = "CANCELLED"
    await db.commit()
    await db.refresh(assessment)

    if was_running:
        scope = assessment.authorized_scope or {}
        target_ip = scope.get("ips", [None])[0]
        await execute_scenario_cleanup(
            db=db,
            tenant_id=tenant_id,
            assessment_id=assessment.id,
            scenario_id=assessment.scenario,
            target_ip=target_ip,
        )

    await log_audit_event(
        db=db,
        tenant_id=tenant_id,
        user_id=user_id,
        action="ADVERSARY_ASSESSMENT_CANCELLED",
        resource_type="adversary_assessment",
        resource_id=str(assessment.id),
        result="SUCCESS",
    )
    return assessment


async def get_assessment(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    assessment_id: uuid.UUID,
) -> AdversaryAssessment | None:
    """Retrieves assessment by ID strictly scoped to tenant."""
    stmt = (
        select(AdversaryAssessment)
        .where(
            AdversaryAssessment.id == assessment_id,
            AdversaryAssessment.tenant_id == tenant_id,
        )
        .options(selectinload(AdversaryAssessment.results))
    )
    res = await db.execute(stmt)
    return res.scalars().first()


async def list_assessments(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    status: str | None = None,
    limit: int = 50,
) -> list[AdversaryAssessment]:
    """Lists assessments for tenant."""
    stmt = (
        select(AdversaryAssessment)
        .where(AdversaryAssessment.tenant_id == tenant_id)
        .options(selectinload(AdversaryAssessment.results))
        .order_by(AdversaryAssessment.created_at.desc())
        .limit(min(limit, 100))
    )
    if status:
        stmt = stmt.where(AdversaryAssessment.status == status.upper())
    res = await db.execute(stmt)
    return list(res.scalars().all())


async def get_assessment_results(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    assessment_id: uuid.UUID,
) -> list[AssessmentResult]:
    """Retrieves all results for an assessment strictly scoped to tenant."""
    stmt = (
        select(AssessmentResult)
        .where(
            AssessmentResult.assessment_id == assessment_id,
            AssessmentResult.tenant_id == tenant_id,
        )
        .order_by(AssessmentResult.completed_at.desc())
    )
    res = await db.execute(stmt)
    return list(res.scalars().all())


class AdversaryService:
    create_assessment = staticmethod(create_assessment)
    authorize_assessment = staticmethod(authorize_assessment)
    start_assessment = staticmethod(start_assessment)
    cancel_assessment = staticmethod(cancel_assessment)
    get_assessment = staticmethod(get_assessment)
    list_assessments = staticmethod(list_assessments)
    get_assessment_results = staticmethod(get_assessment_results)
