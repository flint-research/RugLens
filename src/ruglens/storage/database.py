"""Async SQLAlchemy engine and session management."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import DateTime, Float, Integer, String, Text, func
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from ruglens.core.exceptions import RepositoryError

logger = logging.getLogger(__name__)


class StorageBase(DeclarativeBase):
    """Declarative base for RugLens persistence."""


class AssessmentRow(StorageBase):
    """Indexed summary plus the canonical JSON contract."""

    __tablename__ = "assessments"

    # Monotonic insertion order avoids timestamp-resolution ties on SQLite and
    # low-precision datetime implementations.
    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    assessment_id: Mapped[str] = mapped_column(String(36), unique=True, index=True, nullable=False)
    chain_id: Mapped[int] = mapped_column(Integer, index=True, nullable=False)
    token_address: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    block_number: Mapped[int] = mapped_column(Integer, index=True, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False)
    data_coverage: Mapped[float] = mapped_column(Float, nullable=False)
    engine_version: Mapped[str] = mapped_column(String(32), nullable=False)
    timestamp: Mapped[object] = mapped_column(DateTime(timezone=True), nullable=False)
    report_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[object] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )


class Database:
    """Owns an async engine and session factory."""

    def __init__(self, url: str, *, echo: bool = False) -> None:
        self._url = url
        self._engine: AsyncEngine = create_async_engine(url, echo=echo, pool_pre_ping=True)
        self._session_factory = async_sessionmaker(
            bind=self._engine,
            expire_on_commit=False,
            class_=AsyncSession,
        )
        self._initialized = False
        self._lock = asyncio.Lock()

    @property
    def url(self) -> str:
        """Configured SQLAlchemy URL."""
        return self._url

    async def initialize(self) -> None:
        """Create tables if they do not exist."""
        if self._initialized:
            return
        async with self._lock:
            try:
                async with self._engine.begin() as connection:
                    await connection.run_sync(StorageBase.metadata.create_all)
            except Exception as exc:
                raise RepositoryError(f"Could not initialize database: {exc}") from exc
            self._initialized = True

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        """Yield an initialized session and roll back on error."""
        if not self._initialized:
            await self.initialize()
        session = self._session_factory()
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

    async def close(self) -> None:
        """Dispose the engine connection pool."""
        await self._engine.dispose()
        self._initialized = False
