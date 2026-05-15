"""Per-user, per-channel notification preferences.

Stores the user's mute / mention-only setting for a specific channel. The
absence of a row means "use the default (everything)" — we only persist
rows when the user has actively chosen to deviate from the default.

This table is read on the message-send hot path
(:meth:`NotificationsManager.record_mentions_for_message`) to decide
whether to suppress a notification row for a given recipient + channel
pair. Keep the read pattern point-lookup by composite primary key — no
range queries against this table.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID as SA_UUID
from sqlalchemy.orm import Mapped, mapped_column

from pufferblow.api.database.tables.declarative_base import Base


class NotificationPreferences(Base):
    """One row per (user, channel) when the user has overridden defaults.

    ``muted=True`` — suppress every notification class for this channel.
    ``mention_only=True`` — accept @mentions but suppress channel events
    (reactions to your messages, follow-up notification classes, etc).
    The two are independent flags: ``muted`` wins when both are set.

    v1.0 currently only emits ``type='mention'`` notifications, so
    ``mention_only`` is reserved for forward compatibility — the column
    exists so the wire surface for the prefs endpoint is stable across
    the v1.1 notification-class expansion.
    """

    __tablename__ = "notification_preferences"

    user_id: Mapped[UUID] = mapped_column(
        SA_UUID(as_uuid=True).with_variant(String(36), "sqlite"),
        ForeignKey("users.user_id", ondelete="CASCADE"),
        primary_key=True,
        nullable=False,
    )
    channel_id: Mapped[str] = mapped_column(
        String,
        ForeignKey("channels.channel_id", ondelete="CASCADE"),
        primary_key=True,
        nullable=False,
    )

    muted: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    mention_only: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def to_dict(self) -> dict:
        """Render as a client-facing dict."""
        return {
            "user_id": str(self.user_id),
            "channel_id": self.channel_id,
            "muted": bool(self.muted),
            "mention_only": bool(self.mention_only),
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        """Repr special method."""
        return (
            f"NotificationPreferences(user_id={self.user_id!r}, "
            f"channel_id={self.channel_id!r}, muted={self.muted!r}, "
            f"mention_only={self.mention_only!r})"
        )
