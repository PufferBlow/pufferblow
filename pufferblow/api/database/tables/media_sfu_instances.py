from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from pufferblow.api.database.tables.declarative_base import Base


class MediaSFUInstance(Base):
    """Registry row for one media-sfu deployment heartbeating into this instance."""

    __tablename__ = "media_sfu_instances"

    instance_id: Mapped[str] = mapped_column(String(64), primary_key=True, nullable=False)
    region: Mapped[str] = mapped_column(String(64), default="default", nullable=False, index=True)
    signaling_url: Mapped[str] = mapped_column(String(512), nullable=False)
    # Not currently dialed into by the control plane (there's no documented
    # inbound admin API on media-sfu beyond /healthz /readyz /metrics) — kept
    # for a future draining/admin-control path, hence nullable/optional.
    internal_api_base: Mapped[str | None] = mapped_column(String(512), nullable=True)
    max_total_peers: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    current_peers: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    # "active" accepts new sessions, "draining" keeps existing sessions but is
    # never selected for new ones, "dead" is inferred at read time from a
    # stale last_heartbeat_at rather than written directly by any caller.
    status: Mapped[str] = mapped_column(String(16), default="active", nullable=False, index=True)

    last_heartbeat_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
