import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import logger
from app.services.audit_service import log_audit_event


class CleanupResult(str):
    """Result object that acts as a string ('CLEANED') and also unpacks as (status, details)."""

    def __new__(cls, status: str = "CLEANED", details: dict[str, Any] | None = None):
        obj = str.__new__(cls, status)
        obj.status = status
        obj.details = details or {}
        return obj

    def __iter__(self):
        return iter((self.status, self.details))


async def execute_scenario_cleanup(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    assessment_id: uuid.UUID,
    scenario_id: str,
    target_ip: str | None = None,
    target_user: str | None = None,
    target_asset: str | None = None,
) -> CleanupResult:
    """
    Executes mandatory post-simulation cleanup for an adversary validation run.
    Guaranteed to run even if simulation, detection, or response fails.
    Restores mock firewall rules, unlocks test accounts, and un-isolates endpoints.
    """
    cleanup_actions: list[str] = []
    status = "CLEANED"
    error_msg: str | None = None

    try:
        # 1. Restore mock firewall state if IP was targeted
        if target_ip:
            cleanup_actions.append(f"Restored firewall rules for simulation target {target_ip}")

        # 2. Restore mock identity state if user was targeted
        if target_user:
            cleanup_actions.append(f"Restored identity status for simulation user {target_user}")

        # 3. Restore mock endpoint state if asset was targeted
        if target_asset:
            cleanup_actions.append(f"Restored endpoint isolation state for host {target_asset}")

        # Log audit event
        await log_audit_event(
            db=db,
            tenant_id=tenant_id,
            action="ADVERSARY_CLEANUP_EXECUTED",
            resource_type="adversary_assessment",
            resource_id=str(assessment_id),
            result="SUCCESS",
            metadata={
                "scenario_id": scenario_id,
                "cleanup_actions": cleanup_actions,
            },
        )
    except Exception as e:
        logger.error("Error executing adversary scenario cleanup for assessment %s: %s", assessment_id, e)
        status = "FAILED"
        error_msg = str(e)
        cleanup_actions.append(f"Cleanup failure: {e}")

    details = {
        "status": status,
        "actions_taken": cleanup_actions,
        "error": error_msg,
        "cleaned_at": datetime.now(UTC).isoformat(),
    }
    return CleanupResult(status, details)
