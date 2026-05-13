from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import UUID as SA_UUID
from sqlalchemy.orm import Mapped, mapped_column

from pufferblow.api.database.tables.declarative_base import Base


class Notifications(Base):
    """A delivery-tier notification destined for a single recipient.

    v1.0 only emits ``type='mention'`` rows (the message contained an
    ``@username`` that resolved to the recipient). The schema is intentionally
    type-tagged so future event classes (DM, reaction-to-you, role-grant,
    federated follow) can land without a migration.
    """

    __tablename__ = "notifications"

    notification_id: Mapped[str] = mapped_column(String, primary_key=True, nullable=False)

    # Recipient — every notification belongs to exactly one user.
    user_id: Mapped[UUID] = mapped_column(
        SA_UUID(as_uuid=True).with_variant(String(36), "sqlite"),
        ForeignKey("users.user_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Notification type. Free-form for forward-compatibility; v1.0 = 'mention'.
    type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)

    # The acting user — for 'mention' this is the message sender. Nullable
    # because some future notification classes are server-originated.
    actor_user_id: Mapped[UUID | None] = mapped_column(
        SA_UUID(as_uuid=True).with_variant(String(36), "sqlite"),
        ForeignKey("users.user_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Optional contextual ids. Channel for 'mention'/channel-event types.
    channel_id: Mapped[str | None] = mapped_column(
        String,
        ForeignKey("channels.channel_id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    message_id: Mapped[str | None] = mapped_column(
        String,
        ForeignKey("messages.message_id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    # Null until the recipient explicitly marks it read; never auto-cleared
    # so badge counts stay accurate across reloads.
    read_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    __table_args__ = (
        Index("ix_notifications_user_read", "user_id", "read_at"),
    )

    def to_dict(self) -> dict:
        """Render as a client-facing dict."""
        return {
            "notification_id": self.notification_id,
            "user_id": str(self.user_id),
            "type": self.type,
            "actor_user_id": str(self.actor_user_id) if self.actor_user_id else None,
            "channel_id": self.channel_id,
            "message_id": self.message_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "read_at": self.read_at.isoformat() if self.read_at else None,
        }

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        """Repr special method."""
        return (
            f"Notifications(notification_id={self.notification_id!r}, "
            f"user_id={self.user_id!r}, type={self.type!r}, "
            f"channel_id={self.channel_id!r}, message_id={self.message_id!r}, "
            f"created_at={self.created_at!r}, read_at={self.read_at!r})"
        )
