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
from app.db.session import engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    setup_logging(log_level=settings.LOG_LEVEL, log_format=settings.LOG_FORMAT)
    logger.info(
        f"Initializing {settings.PROJECT_NAME} v{settings.VERSION} [{settings.ENVIRONMENT}]",
        extra={"environment": settings.ENVIRONMENT},
    )

    # In development/test, initialize tables safely with a timeout; in production Alembic manages schema
    if settings.ENVIRONMENT.lower() != "production":
        try:
            async with asyncio.timeout(5.0):
                async with engine.begin() as conn:
                    await conn.run_sync(Base.metadata.create_all)
            logger.info("Database schemas verified.")
        except Exception as exc:
            logger.warning("Database schema auto-creation deferred or non-blocking: %s", exc)
    else:
        logger.info("Production mode active: schema migrations managed via Alembic.")

    yield

    # Shutdown
    logger.info(f"Shutting down {settings.PROJECT_NAME}...")
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
