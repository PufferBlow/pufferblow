"""Who may join this server: its join mode, invitation codes and requests to join.

A server is ``open`` (anyone), ``invite`` (a valid invitation code is needed) or ``request`` (people ask, and the
owner or a moderator decides). These tables are small and independent of ``server_settings`` (which the SQLite test
database does not create), the same way ``federation_settings`` is.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from pufferblow.api.database.tables.declarative_base import Base


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ServerAccess(Base):
    """One row: how people get in."""

    __tablename__ = "server_access"

    access_id: Mapped[str] = mapped_column(String(16), primary_key=True, default="global")
    join_mode: Mapped[str] = mapped_column(String(12), nullable=False, default="open", server_default="open")
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ServerInvites(Base):
    """An invitation code. ``max_uses`` and ``expires_at`` are optional limits; ``revoked_at`` ends it early."""

    __tablename__ = "server_invites"

    code: Mapped[str] = mapped_column(String(32), primary_key=True)
    created_by: Mapped[str] = mapped_column(String(64), nullable=False)
    note: Mapped[str | None] = mapped_column(String(120), nullable=True)
    max_uses: Mapped[int | None] = mapped_column(Integer, nullable=True)
    uses: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)

    def to_dict(self) -> dict:
        now = _now()
        expires = self.expires_at.replace(tzinfo=timezone.utc) if self.expires_at and self.expires_at.tzinfo is None else self.expires_at
        if self.revoked_at is not None:
            state = "revoked"
        elif expires is not None and expires <= now:
            state = "expired"
        elif self.max_uses is not None and self.uses >= self.max_uses:
            state = "used_up"
        else:
            state = "active"
        return {
            "code": self.code,
            "created_by": self.created_by,
            "note": self.note,
            "max_uses": self.max_uses,
            "uses": self.uses,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "state": state,
        }


class ServerJoinRequests(Base):
    """Someone asking to join a ``request`` server.

    ``kind`` is ``local`` (they signed up here and wait, ``user_id`` is that pending account) or ``federated`` (they
    have an account on ``home_host`` and ask with it; no account exists here until they are approved).
    """

    __tablename__ = "server_join_requests"

    request_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    kind: Mapped[str] = mapped_column(String(12), nullable=False)
    user_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    handle: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    home_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    actor_uri: Mapped[str | None] = mapped_column(String(512), nullable=True)
    message: Mapped[str | None] = mapped_column(String(300), nullable=True)
    status: Mapped[str] = mapped_column(String(12), nullable=False, default="pending", index=True)
    decided_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_now)

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "kind": self.kind,
            "user_id": self.user_id,
            "handle": self.handle,
            "home_host": self.home_host,
            "message": self.message,
            "status": self.status,
            "decided_by": self.decided_by,
            "decided_at": self.decided_at.isoformat() if self.decided_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class FederationAssertionNonces(Base):
    """Identity assertions already used, so one captured assertion cannot be replayed."""

    __tablename__ = "federation_assertion_nonces"

    nonce: Mapped[str] = mapped_column(String(64), primary_key=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
