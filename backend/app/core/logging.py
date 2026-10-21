import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

SENSITIVE_KEYS = {
    "password",
    "password_hash",
    "token",
    "access_token",
    "refresh_token",
    "secret",
    "secret_key",
    "api_key",
    "authorization",
    "cookie",
}


def sanitize_data(data: Any) -> Any:
    """Recursively scrub sensitive keys from log records."""
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            if any(sensitive in k.lower() for sensitive in SENSITIVE_KEYS):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = sanitize_data(v)
        return sanitized
    elif isinstance(data, list):
        return [sanitize_data(item) for item in data]
    return data


class StructuredJSONFormatter(logging.Formatter):
    """Production JSON log formatter with sensitive field redaction and correlation ID support."""

    def format(self, record: logging.LogRecord) -> str:
        log_obj: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Include correlation ID if present on record
        if hasattr(record, "request_id"):
            log_obj["request_id"] = record.request_id

        # Include tenant ID if present on record
        if hasattr(record, "tenant_id"):
            log_obj["tenant_id"] = str(record.tenant_id)

        # Include extra attributes if provided in record.__dict__
        if hasattr(record, "extra_data") and isinstance(record.extra_data, dict):
            log_obj["extra"] = sanitize_data(record.extra_data)

        if record.exc_info and not record.exc_text:
            log_obj["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_obj)


def setup_logging(log_level: str = "INFO", log_format: str = "json") -> None:
    """Configure root logger with structured formatter."""
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level.upper())

    # Remove existing handlers to avoid duplicates
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    if log_format.lower() == "json":
        handler.setFormatter(StructuredJSONFormatter())
    else:
        standard_format = "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
        handler.setFormatter(logging.Formatter(standard_format))

    root_logger.addHandler(handler)

    # Silence noisy loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


logger = logging.getLogger("aegissoc")
