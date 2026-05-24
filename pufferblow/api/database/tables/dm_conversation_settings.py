"""Per-conversation DM settings.

Stores knobs that apply to ONE DM conversation as a whole rather
than to individual messages. Currently:

  * ``disappear_after_seconds`` — how long after each message is
    sent before it's auto-deleted. ``None`` = never expire (the
    pre-feature default, kept for back-compat). The default for
    new conversations is 24 hours.

Row is created lazily on first customisation; absence of a row
means "use the instance defaults" (currently: 24h expiry).
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from pufferblow.api.database.tables.declarative_base import Base


class DmConversationSettings(Base):
    """Settings row scoped to a single DM conversation."""

    __tablename__ = "dm_conversation_settings"

    conversation_id: Mapped[str] = mapped_column(
        String, primary_key=True, nullable=False
    )

    # Disappearing-message TTL. None means "never expire" — used
    # when a user explicitly turns the feature off. 0 isn't a
    # valid value (would mean "delete on send"); the route layer
    # rejects it.
    disappear_after_seconds: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def to_dict(self) -> dict:
        """Serialise to the client wire shape."""
        return {
            "conversation_id": self.conversation_id,
            "disappear_after_seconds": self.disappear_after_seconds,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
