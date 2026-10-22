"""The instances this one federates with, and the one setting that frames them (the federation mode)."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from pufferblow.api.database.tables.declarative_base import Base


class PeerInstances(Base):
    """One remote instance and what this instance has decided about it."""

    __tablename__ = "peer_instances"

    #: Lower-cased ``host`` or ``host:port``.
    host: Mapped[str] = mapped_column(String(255), primary_key=True)
    #: ``federating``, ``pending`` (waiting for an admin), ``limited`` or ``blocked``.
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending", index=True)
    #: Only the switches an admin changed by hand; the rest follow the status (see ``api/federation/peers.py``).
    policy_overrides: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # What the instance says about itself (nodeinfo); all optional and only ever as fresh as the last look.
    software: Mapped[str | None] = mapped_column(String(64), nullable=True)
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    users_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    contact: Mapped[str | None] = mapped_column(String(255), nullable=True)
    info_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # What this instance has seen of it.
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    last_activity: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_delivery_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_delivery_ok: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    #: How long the last successful delivery to it took.
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    added_by: Mapped[str | None] = mapped_column(String(64), nullable=True)


class FederationSettings(Base):
    """Instance-wide federation settings, as key and value."""

    __tablename__ = "federation_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(String(255), nullable=False)
