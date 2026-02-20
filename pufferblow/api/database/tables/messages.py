from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import ARRAY, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID as SA_UUID
from sqlalchemy.orm import Mapped, mapped_column

from pufferblow.api.database.tables.declarative_base import Base
from pufferblow.api.utils.current_date import date_in_gmt


class Messages(Base):
    """Messages table"""

    __tablename__ = "messages"
    __allow_unmapped__ = True

    message_id: Mapped[str] = mapped_column(String, primary_key=True, nullable=False)
    hashed_message: Mapped[str] = mapped_column(String, nullable=False)
    raw_message: str | None = None

    sender_id: Mapped[UUID] = mapped_column(
        SA_UUID(as_uuid=True),
        ForeignKey("users.user_id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    channel_id: Mapped[str | None] = mapped_column(
        String,
        ForeignKey("channels.channel_id", ondelete="CASCADE"),
        index=True,
        nullable=True,
    )
    conversation_id: Mapped[str | None] = mapped_column(String, index=True, nullable=True)
    sent_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: date_in_gmt(format="%Y-%m-%d %H:%M:%S"),
        index=True,
    )

    attachments: Mapped[list[str] | None] = mapped_column(
        ARRAY(String), nullable=True
    )

    def to_dict(self) -> dict:
        """Convert message object to dictionary format"""
        return {
            "message_id": self.message_id,
            "hashed_message": self.hashed_message,
            "raw_message": self.raw_message,
            "sender_user_id": str(self.sender_id),
            "channel_id": self.channel_id,
            "conversation_id": self.conversation_id,
            "sent_at": self.sent_at.isoformat() if self.sent_at else None,
            "attachments": self.attachments or [],
        }

    def __repr__(self) -> str:
        return (
            f"Messages(message_id={self.message_id!r}, "
            f"hashed_message={self.hashed_message!r}, "
            f"sender_id={self.sender_id!r}, "
            f"channel_id={self.channel_id!r}, "
            f"conversation_id={self.conversation_id!r}, "
            f"sent_at={self.sent_at!r})"
        )
