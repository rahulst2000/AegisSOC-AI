from datetime import UTC, datetime

from fastapi import APIRouter, Depends, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import get_db

router = APIRouter(tags=["Health & Status"])


@router.get("/health", status_code=status.HTTP_200_OK)
async def health_check(db: AsyncSession = Depends(get_db)):
    """
    Production health check verifying database connectivity and service availability.
    """
    db_status = "connected"
    try:
        await db.execute(text("SELECT 1"))
    except Exception as exc:
        db_status = f"unhealthy: {str(exc)}"

    from app.workers.queue import get_queue_health

    queue_status = await get_queue_health()

    return {
        "status": "healthy" if "unhealthy" not in db_status else "degraded",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "timestamp": datetime.now(UTC).isoformat(),
        "database": db_status,
        "queue": queue_status,
    }


@router.get("/health/ai", status_code=status.HTTP_200_OK)
async def ai_health_status():
    """
    Safe AI provider status verification without exposing secrets.
    Reports provider, model, configuration status, and fallback readiness.
    """
    from app.ai.gateway import get_ai_provider_status

    return {
        "status": "healthy",
        "timestamp": datetime.now(UTC).isoformat(),
        **get_ai_provider_status(),
    }


@router.post("/health/ai/test-connectivity", status_code=status.HTTP_200_OK)
async def ai_connectivity_test():
    """
    Runs a safe synthetic connectivity test against Google Gemini.
    Uses synthetic telemetry only; never sends customer data or credentials.
    """
    from app.ai.gemini_provider import GeminiAIProvider

    provider = GeminiAIProvider()
    return await provider.test_connectivity()
