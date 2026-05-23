"""Friend-request block list — a narrower form of blocking.

This is intentionally NOT a full "block this user" feature (which
would also need to hide their messages, suppress mentions, prevent
DM creation, etc — much bigger surface). It's scoped exactly to
the friend-request graph:

  * If A blocks B, B's `POST /friends/requests` targeting A returns
    403, and any existing pending request from B → A is deleted.
  * Existing accepted friendships are NOT affected — blocking
    incoming requests is independent of being friends. To end an
    existing friendship the user uses `DELETE /friends/{user_id}`
    AND blocks separately.
  * The block is one-way and asymmetric. A blocking B doesn't
    prevent A from sending B a request; it only stops B → A.

Schema:
  * Composite PK on (blocker_id, blocked_id) — at most one row per
    directional pair.
  * Index on blocked_id alone so the read on the request-send hot
    path ("did this addressee block me?") is a single point lookup.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import UUID as SA_UUID
from sqlalchemy.orm import Mapped, mapped_column

from pufferblow.api.database.tables.declarative_base import Base


class FriendRequestBlocks(Base):
    """One row per (blocker → blocked) directional block."""

    __tablename__ = "friend_request_blocks"
    __table_args__ = (
        # Hot read on the send-request path goes
        # `WHERE blocker_id = <addressee> AND blocked_id = <requester>`.
        # The composite PK serves that, but we add an index on
        # `blocked_id` alone for the inverse "am I blocked anywhere?"
        # query (admin / audit use; not on the hot path).
        Index("ix_friend_request_blocks_blocked", "blocked_id"),
    )

    blocker_id: Mapped[UUID] = mapped_column(
        SA_UUID(as_uuid=True).with_variant(String(36), "sqlite"),
        ForeignKey("users.user_id", ondelete="CASCADE"),
        primary_key=True,
        nullable=False,
    )
    blocked_id: Mapped[UUID] = mapped_column(
        SA_UUID(as_uuid=True).with_variant(String(36), "sqlite"),
        ForeignKey("users.user_id", ondelete="CASCADE"),
        primary_key=True,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    def to_dict(self) -> dict:
        return {
            "blocker_id": str(self.blocker_id),
            "blocked_id": str(self.blocked_id),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return (
            f"FriendRequestBlocks(blocker_id={self.blocker_id!r}, "
            f"blocked_id={self.blocked_id!r})"
        )
