"""Friend graph — one table for both pending requests and accepted ties.

A friendship is a directed pair `(requester_id → addressee_id)` plus a
status. We store only ONE row per pair regardless of who eventually
"owns" the relationship — the `status` field carries the lifecycle:

  * ``pending``  — `requester` sent a friend request; `addressee`
                   hasn't decided yet. Only the addressee can accept;
                   either side can cancel (delete the row).
  * ``accepted`` — both sides are friends. Symmetric for queries;
                   asymmetric for "who initiated" provenance, which
                   is still useful for audit / UI ("you sent the
                   request" vs "they sent the request").

A future status of ``blocked`` is intentionally NOT modeled here —
blocking deserves its own table because the semantics (one-way,
hides the blocker from the blocked, suppresses notifications) are
materially different from friendship state. Adding it later means
a separate migration; the friendship row is unaffected.

Lookup pattern:
  * "are users A and B friends?" → query
        ``WHERE (requester = A AND addressee = B)
            OR  (requester = B AND addressee = A)
            AND status = 'accepted'``
  * "list friends of user X" → query both directions, status accepted,
    join through users to get the OTHER side.
  * "incoming requests for user X" → addressee_id = X, status = pending.
  * "outgoing requests by user X"  → requester_id = X, status = pending.

A UNIQUE constraint on the ordered pair prevents duplicate rows; the
manager layer enforces "no swap-direction duplicate" by checking both
directions before insert. (A two-column UNIQUE alone can't catch the
swap; doing it in SQL would need a normalized-pair generated column,
which is more machinery than the foundation pass needs.)
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, Index, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as SA_UUID
from sqlalchemy.orm import Mapped, mapped_column

from pufferblow.api.database.tables.declarative_base import Base


class Friendships(Base):
    """Friendship row — pending request or accepted relationship."""

    __tablename__ = "friendships"
    __table_args__ = (
        # One row per directional pair. Swap-direction duplicates are
        # caught at the manager layer because a SQL-only swap-aware
        # uniqueness would require a normalized-pair expression index
        # (more machinery than the foundation pass needs).
        UniqueConstraint(
            "requester_id", "addressee_id", name="uq_friendships_pair"
        ),
        # The two hot reads — "list friends for user X" walks both
        # directions, so we want both columns indexed individually.
        # The pair UNIQUE constraint above already creates one of
        # those indexes; declare the addressee one explicitly so
        # both directions of the OR-walk are served.
        Index("ix_friendships_addressee", "addressee_id"),
        # Filtering by status (pending vs accepted) on every list
        # query — index on status alone is cheap and skips the
        # full-scan when most rows are accepted.
        Index("ix_friendships_status", "status"),
    )

    friendship_id: Mapped[str] = mapped_column(
        String, primary_key=True, nullable=False
    )

    # `requester_id` is the user who initiated the friend request.
    # `addressee_id` is the user it was sent to. Both stay set after
    # acceptance so the provenance ("you sent the request") survives.
    requester_id: Mapped[UUID] = mapped_column(
        SA_UUID(as_uuid=True).with_variant(String(36), "sqlite"),
        ForeignKey("users.user_id", ondelete="CASCADE"),
        nullable=False,
    )
    addressee_id: Mapped[UUID] = mapped_column(
        SA_UUID(as_uuid=True).with_variant(String(36), "sqlite"),
        ForeignKey("users.user_id", ondelete="CASCADE"),
        nullable=False,
    )

    # ``pending`` — request awaiting addressee response.
    # ``accepted`` — both sides are friends.
    # Stored as plain text rather than a Postgres enum because adding
    # a new state (``blocked`` later, ``rejected_archived`` later) is
    # a schema change for enum types but a no-op for text. The set of
    # legal values is enforced at the manager layer.
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="pending", server_default="pending"
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    def to_dict(self) -> dict:
        """Render as a client-facing dict.

        Doesn't include the requester/addressee user objects — the
        manager layer is responsible for hydrating the "other side"
        when assembling a list response, because the perspective
        (incoming vs outgoing) depends on whose listing it is.
        """
        return {
            "friendship_id": self.friendship_id,
            "requester_id": str(self.requester_id),
            "addressee_id": str(self.addressee_id),
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return (
            f"Friendships(friendship_id={self.friendship_id!r}, "
            f"requester_id={self.requester_id!r}, "
            f"addressee_id={self.addressee_id!r}, "
            f"status={self.status!r})"
        )
