from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as SA_UUID
from sqlalchemy.orm import Mapped, mapped_column

from pufferblow.api.database.tables.declarative_base import Base


class ActivityPubActor(Base):
    """ActivityPubActor class."""
    __tablename__ = "activitypub_actors"

    actor_id: Mapped[UUID] = mapped_column(
        SA_UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    user_id: Mapped[UUID | None] = mapped_column(
        SA_UUID(as_uuid=True),
        ForeignKey("users.user_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    actor_uri: Mapped[str] = mapped_column(String(512), unique=True, nullable=False, index=True)
    preferred_username: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    inbox_uri: Mapped[str] = mapped_column(String(512), nullable=False)
    outbox_uri: Mapped[str] = mapped_column(String(512), nullable=False)
    shared_inbox_uri: Mapped[str | None] = mapped_column(String(512), nullable=True)
    public_key_pem: Mapped[str] = mapped_column(Text, nullable=False)
    private_key_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_local: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    fetched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class ActivityPubFollow(Base):
    """ActivityPubFollow class."""
    __tablename__ = "activitypub_follows"
    __table_args__ = (
        UniqueConstraint("local_actor_uri", "remote_actor_uri", name="uq_ap_follow_pair"),
    )

    follow_id: Mapped[UUID] = mapped_column(
        SA_UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    local_actor_uri: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    remote_actor_uri: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    follow_activity_uri: Mapped[str | None] = mapped_column(String(512), nullable=True, unique=True)
    accepted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class ActivityPubInboxActivity(Base):
    """ActivityPubInboxActivity class."""
    __tablename__ = "activitypub_inbox_activities"

    record_id: Mapped[UUID] = mapped_column(
        SA_UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    activity_uri: Mapped[str] = mapped_column(String(512), nullable=False, unique=True, index=True)
    activity_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    actor_uri: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    target_actor_uri: Mapped[str | None] = mapped_column(String(512), nullable=True, index=True)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class ActivityPubOutboxActivity(Base):
    """ActivityPubOutboxActivity class."""
    __tablename__ = "activitypub_outbox_activities"

    record_id: Mapped[UUID] = mapped_column(
        SA_UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    activity_uri: Mapped[str] = mapped_column(String(512), nullable=False, unique=True, index=True)
    activity_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    actor_uri: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    object_uri: Mapped[str | None] = mapped_column(String(512), nullable=True, index=True)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
