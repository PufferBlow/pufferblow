from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import ARRAY, JSON, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID as SA_UUID
from sqlalchemy.orm import Mapped, mapped_column

from pufferblow.api.database.tables.declarative_base import Base


class MessageReadHistory(Base):
    """MessageReadHistory table"""

    __tablename__ = "message_read_history"

    user_id: Mapped[UUID] = mapped_column(
        SA_UUID(as_uuid=True).with_variant(String(36), "sqlite"),
        ForeignKey("users.user_id", ondelete="CASCADE"),
        primary_key=True,
        nullable=False,
    )
    viewed_messages_ids: Mapped[list[str]] = mapped_column(
        ARRAY(String).with_variant(JSON(), "sqlite"),
        default=list,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        """Repr special method."""
        return (
            f"MessageReadHistory(user_id={self.user_id!r}, "
            f"viewed_messages_ids={self.viewed_messages_ids!r}, "
            f"created_at={self.created_at!r}, "
            f"updated_at={self.updated_at!r})"
        )

    def to_dict(self) -> dict:
        """To dict."""
        return {
            "user_id": self.user_id,
            "viewed_messages_ids": self.viewed_messages_ids,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
