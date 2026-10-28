import asyncio
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.api.v1.router import api_v1_router
from app.core.config import settings
from app.core.logging import logger, setup_logging
from app.core.middleware import (
    CorrelationIdMiddleware,
    ErrorHandlingMiddleware,
    SecurityHeadersMiddleware,
)
from app.db.base import Base
from app.db.session import AsyncSessionLocal, engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    setup_logging(log_level=settings.LOG_LEVEL, log_format=settings.LOG_FORMAT)
    logger.info(
        f"Initializing {settings.PROJECT_NAME} v{settings.VERSION} [{settings.ENVIRONMENT}]",
        extra={"environment": settings.ENVIRONMENT},
    )

    # Database schema management:
    # In SQLite environments (e.g. ad-hoc local testing), ensure Base models are initialized.
    # In PostgreSQL (production/staging), schema is managed authoritatively via Alembic migrations.
    if engine.dialect.name == "sqlite":
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("Local SQLite database schemas initialized.")
        except Exception as exc:
            logger.warning("Local SQLite schema initialization: %s", exc)
    else:
        logger.info("Database schemas managed authoritatively via Alembic migrations.")

    # 1. Synchronize baseline detection rules into database
    try:
        from app.detection.rule_loader import sync_rules_to_db

        session_factory = getattr(app.state, "session_factory", AsyncSessionLocal)
        async with session_factory() as session:
            synced_rules = await sync_rules_to_db(session)
            logger.info("Synchronized %d baseline detection rules into database.", len(synced_rules))
    except Exception as exc:
        logger.error("Failed to synchronize baseline detection rules: %s", exc, exc_info=True)

    # 2. Start background detection and correlation workers
    if not getattr(app.state, "workers_running", False):
        try:
            from app.workers.correlation_worker import CorrelationWorker
            from app.workers.detection_worker import DetectionWorker

            session_factory = getattr(app.state, "session_factory", AsyncSessionLocal)
            detection_worker = DetectionWorker()
            correlation_worker = CorrelationWorker()

            stop_event = asyncio.Event()
            worker_tasks = [
                asyncio.create_task(
                    detection_worker.run_worker_loop(
                        session_factory=session_factory,
                        stop_event=stop_event,
                        poll_interval=1.0,
                    ),
                    name="detection_worker_loop",
                ),
                asyncio.create_task(
                    correlation_worker.run_worker_loop(
                        session_factory=session_factory,
                        stop_event=stop_event,
                        poll_interval=1.0,
                    ),
                    name="correlation_worker_loop",
                ),
            ]
            app.state.workers_running = True
            app.state.worker_stop_event = stop_event
            app.state.worker_tasks = worker_tasks
            logger.info("Background detection and correlation workers started successfully.")
        except Exception as exc:
            logger.error("Failed to initialize background workers: %s", exc, exc_info=True)

    yield

    # Shutdown
    logger.info(f"Shutting down {settings.PROJECT_NAME}...")

    # Stop background workers cleanly
    if getattr(app.state, "workers_running", False):
        logger.info("Signaling background workers to stop...")
        stop_event = getattr(app.state, "worker_stop_event", None)
        if stop_event:
            stop_event.set()
        tasks = getattr(app.state, "worker_tasks", [])
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        app.state.workers_running = False
        logger.info("Background workers shut down cleanly.")

    await engine.dispose()
    logger.info("Database connections terminated.")


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Evidence-Grounded Autonomous Security Operations Platform — Production Foundation",
    version=settings.VERSION,
    lifespan=lifespan,
    docs_url="/docs" if settings.ENVIRONMENT != "production" else None,
    redoc_url="/redoc" if settings.ENVIRONMENT != "production" else None,
)

# 1. Error Handling Middleware (outermost for exception catching)
app.add_middleware(ErrorHandlingMiddleware)

# 2. Security Headers
app.add_middleware(SecurityHeadersMiddleware)

# 3. Request Correlation ID
app.add_middleware(CorrelationIdMiddleware)

# 4. CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.get_cors_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-Response-Time-Ms"],
)


# Root health endpoint
@app.get("/health", status_code=status.HTTP_200_OK, tags=["Health"])
async def root_health():
    """Root health probe for container orchestrators and load balancers."""
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "timestamp": datetime.now(UTC).isoformat(),
    }


@app.get("/healthz", status_code=status.HTTP_200_OK, tags=["Health"])
async def liveness_probe():
    """Ultra-lightweight liveness probe for orchestrators and Render healthcheck."""
    return {"status": "ok"}


@app.get("/readyz", status_code=status.HTTP_200_OK, tags=["Health"])
async def readiness_probe():
    """Lightweight readiness probe verifying DB connectivity via SELECT 1."""
    try:
        async with asyncio.timeout(2.0):
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
        return {"status": "ready", "database": "connected"}
    except Exception as exc:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "degraded", "database": f"unavailable: {exc}"},
        )


# Mount API v1
app.include_router(api_v1_router, prefix="/api/v1")
