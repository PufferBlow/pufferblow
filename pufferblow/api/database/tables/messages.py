from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import JSON, DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import TSVECTOR, UUID as SA_UUID
from sqlalchemy.orm import Mapped, mapped_column

from pufferblow.api.database.tables.declarative_base import Base


class Messages(Base):
    """Messages table"""

    __tablename__ = "messages"
    __allow_unmapped__ = True

    # Composite btree for keyset pagination (channel_id, sent_at,
    # message_id). Declared here so `create_all` builds it on fresh
    # installs of both dialects; the idempotent migration in
    # `DatabaseHandler._apply_messages_scaleout_migration` also issues a
    # `CREATE INDEX IF NOT EXISTS` so upgrading instances pick it up.
    #
    # The GIN index on `search_tokens` is deliberately NOT declared
    # here — its DDL (`USING gin`, partial `WHERE search_tokens IS NOT
    # NULL`) is Postgres-only and SQLAlchemy would attempt to render it
    # on SQLite too. The migration helper creates it explicitly on
    # Postgres; SQLite uses the in-Python substring fallback and never
    # needs a search index.
    __table_args__ = (
        Index(
            "ix_messages_channel_sent_at_msg",
            "channel_id",
            "sent_at",
            "message_id",
        ),
    )

    message_id: Mapped[str] = mapped_column(String, primary_key=True, nullable=False)
    hashed_message: Mapped[str] = mapped_column(String, nullable=False)
    raw_message: str | None = None

    sender_id: Mapped[UUID] = mapped_column(
        SA_UUID(as_uuid=True).with_variant(String(36), "sqlite"),
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
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    attachments: Mapped[list | None] = mapped_column(JSON(), nullable=True)

    # Server-side ranked-search column. Populated from plaintext at write
    # time (see `MessagesManager._build_message_record`), kept NULL on
    # SQLite (the test harness uses the in-Python fallback). The GIN index
    # in __table_args__ is filtered on `IS NOT NULL` so it stays small on
    # instances that haven't yet backfilled historic rows.
    #
    # `TSVECTOR` is Postgres-only; we declare a `String` fallback for
    # SQLite so the column exists in both dialects (the SQLite path never
    # writes to it).
    search_tokens: Mapped[str | None] = mapped_column(
        TSVECTOR().with_variant(String, "sqlite"),
        nullable=True,
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
        """Repr special method."""
        return (
            f"Messages(message_id={self.message_id!r}, "
            f"hashed_message={self.hashed_message!r}, "
            f"sender_id={self.sender_id!r}, "
            f"channel_id={self.channel_id!r}, "
            f"conversation_id={self.conversation_id!r}, "
            f"sent_at={self.sent_at!r})"
        )
