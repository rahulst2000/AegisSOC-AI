from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import settings

# Determine engine parameters
database_url = settings.get_database_url()

engine_kwargs = {
    "echo": settings.DEBUG,
    "future": True,
}

if database_url.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    engine_kwargs["pool_pre_ping"] = True
    engine_kwargs["pool_size"] = 10
    engine_kwargs["max_overflow"] = 20
    if (
        "localhost" not in database_url
        and "127.0.0.1" not in database_url
        and settings.ENVIRONMENT.lower() == "production"
    ):
        engine_kwargs["connect_args"] = {"ssl": "require"}

engine: AsyncEngine = create_async_engine(database_url, **engine_kwargs)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency that provides an asynchronous database session per request."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
