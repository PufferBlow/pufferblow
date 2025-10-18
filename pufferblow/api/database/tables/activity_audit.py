from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from sqlalchemy import String, Integer, DateTime, Text, JSON, UUID, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from pufferblow.api.database.tables.declarative_base import Base
from pufferblow.api.utils.current_date import date_in_gmt

class ActivityAudit(Base):
    """Activity audit table to track individual system activities like file uploads, user joins, etc."""
    __tablename__ = "activity_audit"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    activity_id: Mapped[str] = mapped_column(String(36), nullable=False, unique=True)  # UUID as string
    activity_type: Mapped[str] = mapped_column(String(50), nullable=False)  # 'file_upload', 'user_joined', 'channel_created', etc.
    user_id: Mapped[str] = mapped_column(String(36), nullable=False)  # User who performed the activity

    # Activity details
    title: Mapped[str] = mapped_column(String(255), nullable=False)  # Human-readable title
    description: Mapped[str] = mapped_column(Text, nullable=True)  # Optional detailed description
    metadata_json: Mapped[str] = mapped_column(Text, nullable=True)  # JSON string for additional metadata

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=date_in_gmt, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=date_in_gmt, onupdate=date_in_gmt, nullable=False)

    def __repr__(self) -> str:
        return (
            f"ActivityAudit(activity_id={self.activity_id!r}, activity_type={self.activity_type!r}, "
            f"user_id={self.user_id!r}, title={self.title!r})"
        )
