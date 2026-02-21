from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from pufferblow.api.database.tables.declarative_base import Base


class VoiceSession(Base):
    """Tracks one active/inactive SFU voice session bound to a channel."""

    __tablename__ = "voice_sessions"

    session_id: Mapped[str] = mapped_column(String(64), primary_key=True, nullable=False)
    channel_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    server_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    backend: Mapped[str] = mapped_column(String(24), default="sfu_v2", nullable=False)
    quality_profile: Mapped[str] = mapped_column(String(24), default="balanced", nullable=False)
    signaling_url: Mapped[str] = mapped_column(String(512), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    created_by: Mapped[str] = mapped_column(String(64), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False
    )
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class VoiceSessionParticipant(Base):
    """Tracks membership and media-state of a user in a voice session."""

    __tablename__ = "voice_session_participants"
    __table_args__ = (
        UniqueConstraint("session_id", "user_id", name="uq_voice_session_participant"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    username: Mapped[str | None] = mapped_column(String(64), nullable=True)

    is_connected: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    is_muted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_deafened: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_speaking: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    joined_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    disconnected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class VoiceSessionEvent(Base):
    """Auditable session events emitted by control/media plane."""

    __tablename__ = "voice_session_events"

    event_id: Mapped[str] = mapped_column(String(64), primary_key=True, nullable=False)
    session_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    user_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class VoiceJoinToken(Base):
    """One-time use token registry for SFU join JWT replay protection."""

    __tablename__ = "voice_join_tokens"

    token_id: Mapped[str] = mapped_column(String(64), primary_key=True, nullable=False)
    session_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
