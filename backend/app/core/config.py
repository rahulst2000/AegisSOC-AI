import os

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # General
    PROJECT_NAME: str = "AegisSOC AI"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False

    # Server
    BACKEND_HOST: str = "0.0.0.0"  # nosec: B104
    BACKEND_PORT: int = Field(
        default=8000,
        validation_alias=AliasChoices("PORT", "BACKEND_PORT"),
        description="Backend listening port",
    )

    # Cryptography & JWT
    SECRET_KEY: str = Field(
        default="change-this-in-production-generate-with-openssl-rand-hex-32",
        description="JWT encryption secret key",
    )
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # CORS
    ALLOWED_ORIGINS: str | list[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ]

    # Database
    DATABASE_URL: str = Field(
        default="",
        description="Direct database URL. If omitted, built from POSTGRES_* fields.",
    )
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "aegissoc_user"
    POSTGRES_PASSWORD: str = "DEMO_PASSWORD=<configure locally>"
    POSTGRES_DB: str = "aegissoc_db"

    # Redis
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: str = ""
    REDIS_URL: str = ""

    # Rate limiting
    RATE_LIMIT_PER_MINUTE: int = 100

    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "json"

    # AI & Google Gemini Configuration
    GEMINI_API_KEY: str = Field(
        default="",
        description="Google Gemini API key. Never expose in logs, API responses, or frontend.",
    )
    AI_PROVIDER: str = Field(default="gemini", description="AI Provider: gemini, deterministic, openai")
    AI_MODEL: str = Field(default="gemini-2.5-flash", description="Default AI model")
    AI_REQUEST_TIMEOUT_SECONDS: float = Field(default=30.0, description="Max timeout for AI requests")
    AI_MAX_RETRIES: int = Field(default=2, description="Max retries for transient AI API errors")
    AI_MAX_INPUT_CHARS: int = Field(default=50000, description="Max chars in serialized context to prevent DoS")
    AI_MAX_OUTPUT_TOKENS: int = Field(default=4096, description="Max output tokens for AI response")

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: str | list[str]) -> list[str]:
        if isinstance(v, str):
            origins = [origin.strip() for origin in v.split(",") if origin.strip()]
        elif isinstance(v, list):
            origins = [str(origin).strip() for origin in v if str(origin).strip()]
        else:
            origins = []
        return origins

    @field_validator("SECRET_KEY")
    @classmethod
    def validate_secret_key(cls, v: str, info) -> str:
        env = os.getenv("ENVIRONMENT", "development")
        if env.lower() == "production" and ("change-this" in v or len(v) < 32):
            raise ValueError(
                "In production, SECRET_KEY must be a cryptographically secure string of at least 32 characters."
            )
        return v

    def get_cors_origins(self) -> list[str]:
        origins = self.ALLOWED_ORIGINS if isinstance(self.ALLOWED_ORIGINS, list) else []
        if self.ENVIRONMENT.lower() == "production":
            # Security Rule: Never use allow_origins=["*"] in production configuration.
            sanitized = [orig for orig in origins if orig != "*"]
            if not sanitized:
                sanitized = ["https://soc.aegis.internal"]
            return sanitized
        return origins

    def get_database_url(self) -> str:
        if self.DATABASE_URL:
            # Normalize driver for asyncpg if standard postgresql:// provided
            url = self.DATABASE_URL
            if url.startswith("postgresql://"):
                url = url.replace("postgresql://", "postgresql+asyncpg://", 1)

            # asyncpg does not accept libpq's sslmode URL parameter.
            # SSL is configured through connect_args in db/session.py.
            if url.startswith("postgresql+asyncpg://"):
                from urllib.parse import (
                    parse_qsl,
                    urlencode,
                    urlsplit,
                    urlunsplit,
                )

                parts = urlsplit(url)
                query_params = [
                    (key, value)
                    for key, value in parse_qsl(
                        parts.query,
                        keep_blank_values=True,
                    )
                    if key.lower() != "sslmode"
                ]
                url = urlunsplit(
                    (
                        parts.scheme,
                        parts.netloc,
                        parts.path,
                        urlencode(query_params),
                        parts.fragment,
                    )
                )

            return url
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@"
            f"{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    def get_sync_database_url(self) -> str:
        """Returns standard synchronous URL for Alembic or sync helpers."""
        if self.DATABASE_URL:
            url = self.DATABASE_URL
            if url.startswith("postgresql+asyncpg://"):
                url = url.replace("postgresql+asyncpg://", "postgresql://", 1)
            elif url.startswith("sqlite+aiosqlite://"):
                url = url.replace("sqlite+aiosqlite://", "sqlite://", 1)
            return url
        return (
            f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@"
            f"{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    def get_redis_url(self) -> str:
        if self.REDIS_URL:
            return self.REDIS_URL
        if self.REDIS_PASSWORD:
            return f"redis://:{self.REDIS_PASSWORD}@{self.REDIS_HOST}:{self.REDIS_PORT}/0"
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/0"


settings = Settings()
