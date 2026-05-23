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

    The ``emoji`` column carries either:

      * A Unicode emoji (one or more codepoints, e.g. ``"👍"`` or
        ``"👨‍👩‍👧"`` — the latter is a multi-codepoint ZWJ sequence).
      * An instance sticker reaction key of the form
        ``"sticker:<sticker_id>"`` where ``<sticker_id>`` is the UUID
        of a row in ``server_stickers``. The 7-char prefix +
        36-char UUID totals 43 chars, so the column width must
        comfortably exceed 32 — we use 64 to leave headroom for
        future reaction types (e.g. ``"custom:<id>"`` if per-server
        custom emoji land later) without another schema change.

    Render-side code routes the value by inspecting the ``sticker:``
    prefix; the storage layer doesn't care which shape it is.
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
    # Widened from 32 → 64 to accommodate sticker-reaction keys
    # (``sticker:<36-char-uuid>``); see class docstring.
    emoji: Mapped[str] = mapped_column(String(64), nullable=False)
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
