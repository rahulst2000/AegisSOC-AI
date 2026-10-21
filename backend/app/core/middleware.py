import logging
import time
import uuid
from collections.abc import Callable

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("aegissoc.middleware")


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """
    Ensures every incoming HTTP request has a unique correlation ID (X-Request-ID).
    Propagates the ID to request state, downstream logs, and outgoing response headers.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = request.headers.get("X-Request-ID")
        if not request_id:
            request_id = str(uuid.uuid4())

        # Store in request state for downstream handlers and audit loggers
        request.state.request_id = request_id

        start_time = time.perf_counter()
        response = await call_next(request)
        process_time_ms = round((time.perf_counter() - start_time) * 1000, 2)

        # Attach to outgoing response headers
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time-Ms"] = str(process_time_ms)
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Applies defense-in-depth HTTP security headers to all responses.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none';"
        return response


class ErrorHandlingMiddleware(BaseHTTPMiddleware):
    """
    Catches any unhandled exceptions, ensures structured logging with correlation ID,
    and returns a standardized error payload without exposing sensitive internal stack traces.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        try:
            return await call_next(request)
        except Exception as exc:
            request_id = getattr(request.state, "request_id", "unknown")
            logger.error(
                f"Unhandled server error processing {request.method} {request.url.path}: {str(exc)}",
                exc_info=True,
                extra={"request_id": request_id},
            )
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={
                    "error": "InternalServerError",
                    "detail": "An internal error occurred. Please contact security operations.",
                    "request_id": request_id,
                },
                headers={"X-Request-ID": request_id},
            )
