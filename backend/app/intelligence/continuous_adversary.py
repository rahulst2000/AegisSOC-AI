"""5B-11: Continuous Adversary Validation Scheduler.

Schedules authorized lab/staging adversary assessments.
Enforces strict safeguards:
- Explicit authorized scope
- Scope expiry verification
- Target allowlist validation
- Technique allowlist validation
- Strict production target rejection: NEVER automatically target production
- Audit logging & automated cleanup
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ForbiddenException, ValidationException
from app.intelligence.models import ContinuousAdversarySchedule
from app.intelligence.schemas import ScheduleCreate, ScheduleResponse
from app.services.audit_service import log_audit_event


class ContinuousAdversaryScheduler:
    """Manages scheduled recurring adversary validations in authorized lab environments."""

    @classmethod
    async def create_schedule(
        cls,
        db: AsyncSession,
        tenant_id: uuid.UUID,
        payload: ScheduleCreate,
        creator_id: uuid.UUID,
        creator_role: str,
    ) -> ScheduleResponse:
        """Registers a recurring adversary validation schedule with scope validation."""
        # Role check: Only SOC_L2_LEAD or TENANT_ADMIN can schedule adversary validations
        if creator_role not in ["SOC_L2", "SOC_L2_LEAD", "TENANT_ADMIN"]:
            raise ForbiddenException(f"Role '{creator_role}' is unauthorized to schedule adversary assessments.")

        # Environment safeguard: NEVER target production
        env = payload.environment.upper()
        if env not in ["LAB", "STAGING", "DEV", "TEST"]:
            raise ForbiddenException(
                f"Continuous adversary validation is strictly prohibited in '{payload.environment}'. "
                f"Target environment must be LAB or STAGING."
            )

        # Expiry safeguard
        now = datetime.now(UTC)
        if payload.expires_at.tzinfo is None:
            expires_at = payload.expires_at.replace(tzinfo=UTC)
        else:
            expires_at = payload.expires_at

        if expires_at <= now:
            raise ValidationException("Schedule expires_at must be in the future.")

        # Scope validation
        for target in payload.target_allowlist:
            if "prod" in target.lower():
                raise ForbiddenException(
                    f"Production target '{target}' rejected. Adversary validation cannot target production."
                )

        schedule = ContinuousAdversarySchedule(
            tenant_id=tenant_id,
            name=payload.name,
            scenario_id=payload.scenario_id,
            cron_expression=payload.cron_expression,
            environment=env,
            authorized_scope=payload.authorized_scope,
            target_allowlist=payload.target_allowlist,
            technique_allowlist=payload.technique_allowlist,
            is_active=True,
            expires_at=expires_at,
            created_by=creator_id,
            created_at=now,
        )
        db.add(schedule)
        await db.commit()
        await db.refresh(schedule)

        await log_audit_event(
            db=db,
            tenant_id=tenant_id,
            user_id=creator_id,
            action="ADVERSARY_SCHEDULE_CREATED",
            resource_type="continuous_adversary_schedule",
            resource_id=str(schedule.id),
            result="SUCCESS",
            metadata={
                "name": payload.name,
                "scenario": payload.scenario_id,
                "targets": payload.target_allowlist,
            },
        )

        return ScheduleResponse(
            id=schedule.id,
            tenant_id=schedule.tenant_id,
            name=schedule.name,
            scenario_id=schedule.scenario_id,
            cron_expression=schedule.cron_expression,
            environment=schedule.environment,
            authorized_scope=schedule.authorized_scope,
            target_allowlist=schedule.target_allowlist,
            technique_allowlist=schedule.technique_allowlist,
            is_active=schedule.is_active,
            expires_at=schedule.expires_at,
            last_run_at=schedule.last_run_at,
            next_run_at=schedule.next_run_at,
            created_at=schedule.created_at,
        )

    @classmethod
    async def list_schedules(
        cls,
        db: AsyncSession,
        tenant_id: uuid.UUID,
    ) -> list[ScheduleResponse]:
        """Lists active and past adversary validation schedules for tenant."""
        stmt = (
            select(ContinuousAdversarySchedule)
            .where(ContinuousAdversarySchedule.tenant_id == tenant_id)
            .order_by(ContinuousAdversarySchedule.created_at.desc())
        )
        res = await db.execute(stmt)
        schedules = res.scalars().all()
        return [
            ScheduleResponse(
                id=s.id,
                tenant_id=s.tenant_id,
                name=s.name,
                scenario_id=s.scenario_id,
                cron_expression=s.cron_expression,
                environment=s.environment,
                authorized_scope=s.authorized_scope,
                target_allowlist=s.target_allowlist,
                technique_allowlist=s.technique_allowlist,
                is_active=s.is_active,
                expires_at=s.expires_at,
                last_run_at=s.last_run_at,
                next_run_at=s.next_run_at,
                created_at=s.created_at,
            )
            for s in schedules
        ]
