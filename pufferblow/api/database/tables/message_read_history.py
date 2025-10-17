from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional
from uuid import UUID
from sqlalchemy import String, DateTime, ARRAY, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID as SA_UUID
from pufferblow.api.database.tables.declarative_base import Base
from pufferblow.api.utils.current_date import date_in_gmt


class MessageReadHistory(Base):
    """MessageReadHistory table"""
    __tablename__ = "message_read_history"

    user_id: Mapped[UUID] = mapped_column(SA_UUID(as_uuid=True), ForeignKey("users.user_id", ondelete="CASCADE"), primary_key=True, nullable=False)
    viewed_messages_ids: Mapped[List[str]] = mapped_column(
        ARRAY(String),
        default=list,  # Avoid mutable default
        nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=date_in_gmt,
        nullable=False
    )
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    def __repr__(self) -> str:
        return (
            f"MessageReadHistory(user_id={self.user_id!r}, "
            f"viewed_messages_ids={self.viewed_messages_ids!r}, "
            f"created_at={self.created_at!r}, "
            f"updated_at={self.updated_at!r})"
        )

    def to_dict(self) -> dict:
        return {
            "user_id": self.user_id,
            "viewed_messages_ids": self.viewed_messages_ids,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }
