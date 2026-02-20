from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID as SA_UUID
from sqlalchemy.orm import Mapped, mapped_column

from pufferblow.api.database.tables.declarative_base import Base


class DecentralizedAuthChallenge(Base):
    __tablename__ = "decentralized_auth_challenges"

    challenge_id: Mapped[UUID] = mapped_column(
        SA_UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    user_id: Mapped[UUID] = mapped_column(
        SA_UUID(as_uuid=True),
        ForeignKey("users.user_id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    node_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    challenge_nonce: Mapped[str] = mapped_column(String(255), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    consumed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class DecentralizedNodeSession(Base):
    __tablename__ = "decentralized_node_sessions"

    session_id: Mapped[UUID] = mapped_column(
        SA_UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    user_id: Mapped[UUID] = mapped_column(
        SA_UUID(as_uuid=True),
        ForeignKey("users.user_id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    node_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    node_public_key: Mapped[str] = mapped_column(Text, nullable=False)
    session_token_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    session_token_hint: Mapped[str] = mapped_column(String(16), nullable=False)
    scopes: Mapped[str] = mapped_column(String(255), default="chat:read,chat:write")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
