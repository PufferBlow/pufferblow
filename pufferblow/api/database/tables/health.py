"""What the instance remembers about its own health: a count per day, and the incidents.

``instance_uptime_day`` keeps one row per day with how many times the instance was checked and how many
of those checks found everything working, which is what the "uptime, 90 days" bar is drawn from.
``instance_incident`` is opened when a check finds something wrong and resolved when it is right again,
so the page can say what happened and for how long.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from pufferblow.api.database.tables.declarative_base import Base


class InstanceUptimeDay(Base):
    __tablename__ = "instance_uptime_day"

    #: ``YYYY-MM-DD`` in UTC.
    day: Mapped[str] = mapped_column(String(10), primary_key=True)
    checks: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ok: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class InstanceIncident(Base):
    __tablename__ = "instance_incident"

    incident_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    #: ``investigating`` while it lasts, ``resolved`` after.
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="investigating", index=True)
    body: Mapped[str] = mapped_column(Text, nullable=False, default="")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
