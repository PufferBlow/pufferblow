"""Remembered results of mutating commands, so a retry never repeats the effect."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from pufferblow.api.database.tables.declarative_base import Base


class CommandIdempotency(Base):
    """One row per (principal, operation, key).

    The row is inserted as ``pending`` before the mutation runs and flipped to
    ``completed`` with the stored result afterwards. A retry that finds a
    ``completed`` row returns the stored result; one that finds a fresh
    ``pending`` row is told to try again shortly, and a stale ``pending`` row
    (the process died mid-command) is taken over.
    """

    __tablename__ = "command_idempotency"
    __table_args__ = (Index("ix_command_idempotency_created_at", "created_at"),)

    principal_id: Mapped[str] = mapped_column(String, primary_key=True, nullable=False)
    operation: Mapped[str] = mapped_column(String, primary_key=True, nullable=False)
    key: Mapped[str] = mapped_column(String, primary_key=True, nullable=False)

    status: Mapped[str] = mapped_column(String, nullable=False, default="pending")
    result: Mapped[dict | None] = mapped_column(JSON(), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
