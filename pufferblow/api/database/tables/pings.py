from __future__ import annotations

from datetime import datetime, timezone, timedelta
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.dialects.postgresql import UUID as SA_UUID
from sqlalchemy.orm import Mapped, mapped_column

from pufferblow.api.database.tables.declarative_base import Base

# Default TTL: 5 minutes for a ping to be acked before timeout
DEFAULT_PING_TTL_SECONDS = 300


class Pings(Base):
    """
    Pings table — stores all ping interactions (local, federated, instance).

    Ping lifecycle:
        sent -> delivered -> acked
                          -> timeout  (if no ack within expires_at)
        sent -> failed              (delivery error)
    """

    __tablename__ = "pings"
    __allow_unmapped__ = True

    ping_id: Mapped[UUID] = mapped_column(
        SA_UUID(as_uuid=True).with_variant(String(36), "sqlite"),
        primary_key=True,
        default=uuid4,
        nullable=False,
    )

    # "local" | "federated" | "instance"
    ping_type: Mapped[str] = mapped_column(
        String(32), nullable=False, index=True, default="local"
    )

    # Who sent the ping (always a local user)
    sender_id: Mapped[UUID] = mapped_column(
        SA_UUID(as_uuid=True).with_variant(String(36), "sqlite"),
        ForeignKey("users.user_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Local or shadow user representing the recipient (nullable for instance pings)
    target_user_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True, index=True
    )

    # Fully-qualified ActivityPub actor URI of the recipient (used for federation)
    target_actor_uri: Mapped[str | None] = mapped_column(
        String(512), nullable=True, index=True
    )

    # Base URL of the remote instance (used for instance pings)
    target_instance_url: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # "sent" | "delivered" | "acked" | "timeout" | "failed"
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="sent", index=True
    )

    # Round-trip time in milliseconds — filled when acked
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # HTTP status / round-trip for instance pings
    instance_http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    instance_latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # ActivityPub activity URI for the outgoing Ping activity (federated only)
    activity_uri: Mapped[str | None] = mapped_column(
        String(512), nullable=True, unique=True, index=True
    )

    # ActivityPub activity URI of the original Ping (used on the receiver side)
    original_activity_uri: Mapped[str | None] = mapped_column(
        String(512), nullable=True, index=True
    )

    # Whether this record is for the sender (True) or the recipient (False)
    is_sender: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Optional short message body attached to the ping
    message: Mapped[str | None] = mapped_column(String(500), nullable=True)

    sent_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    acked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # When the ping automatically transitions to "timeout" if not acked
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc) + timedelta(seconds=DEFAULT_PING_TTL_SECONDS),
    )

    # Extra metadata (error messages, remote response bodies, etc.)
    metadata_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    def to_dict(self) -> dict:
        """Serialize to a JSON-safe dict for API responses and WebSocket payloads."""
        return {
            "ping_id": str(self.ping_id),
            "ping_type": self.ping_type,
            "sender_id": str(self.sender_id),
            "target_user_id": self.target_user_id,
            "target_actor_uri": self.target_actor_uri,
            "target_instance_url": self.target_instance_url,
            "status": self.status,
            "latency_ms": self.latency_ms,
            "instance_http_status": self.instance_http_status,
            "instance_latency_ms": self.instance_latency_ms,
            "activity_uri": self.activity_uri,
            "original_activity_uri": self.original_activity_uri,
            "is_sender": self.is_sender,
            "message": self.message,
            "sent_at": self.sent_at.isoformat() if self.sent_at else None,
            "acked_at": self.acked_at.isoformat() if self.acked_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "metadata": self.metadata_json or {},
        }

    def __repr__(self) -> str:
        return (
            f"Pings(ping_id={self.ping_id!r}, type={self.ping_type!r}, "
            f"sender={self.sender_id!r}, status={self.status!r})"
        )
