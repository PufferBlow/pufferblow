from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, PrimaryKeyConstraint, String
from sqlalchemy.dialects.postgresql import UUID as SA_UUID
from sqlalchemy.orm import Mapped, mapped_column

from pufferblow.api.database.tables.declarative_base import Base


class MessageReactions(Base):
    """One reaction by one user on one message with one specific emoji.

    A composite primary key on ``(message_id, user_id, emoji)`` enforces that a
    user can only react once with a given emoji to a given message. A user can
    still apply multiple distinct emoji to the same message.
    """

    __tablename__ = "message_reactions"

    message_id: Mapped[str] = mapped_column(
        String,
        ForeignKey("messages.message_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[UUID] = mapped_column(
        SA_UUID(as_uuid=True).with_variant(String(36), "sqlite"),
        ForeignKey("users.user_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    emoji: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    __table_args__ = (
        PrimaryKeyConstraint("message_id", "user_id", "emoji", name="pk_message_reactions"),
    )

    def to_dict(self) -> dict:
        """To dict."""
        return {
            "message_id": self.message_id,
            "user_id": str(self.user_id),
            "emoji": self.emoji,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        """Repr special method."""
        return (
            f"MessageReactions(message_id={self.message_id!r}, "
            f"user_id={self.user_id!r}, emoji={self.emoji!r}, "
            f"created_at={self.created_at!r})"
        )
