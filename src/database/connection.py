"""
Database connection manager for SentinelEye Agent.

Uses SQLAlchemy async engine for non-blocking database operations.
"""

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from src.core.config import get_settings
from src.utils.logger import get_logger

logger = get_logger(__name__)


# Base class - all database models inherit from this
class Base(DeclarativeBase):
    pass


class DatabaseManager:
    """Manages database connections and sessions."""

    def __init__(self):
        self._engine: AsyncEngine | None = None
        self._session_factory: async_sessionmaker | None = None

    async def initialize(self):
        """Start database connection. Call once at app startup."""
        settings = get_settings()

        logger.info(f"Connecting to database...")

        self._engine = create_async_engine(
            settings.database_url,
            echo=settings.debug,
        )

        self._session_factory = async_sessionmaker(
            bind=self._engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

        # Create all tables
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        logger.info("Database connected and tables created!")

    async def get_session(self) -> AsyncSession:
        """Get a new database session."""
        if self._session_factory is None:
            raise RuntimeError("Database not initialized!")
        return self._session_factory()

    async def shutdown(self):
        """Close database connection."""
        if self._engine:
            await self._engine.dispose()
            logger.info("Database connection closed.")


# Single instance for entire app
db_manager = DatabaseManager()