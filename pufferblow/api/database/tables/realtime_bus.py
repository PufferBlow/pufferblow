"""What the workers of one server share so a realtime event reaches everyone, whichever worker handled the request.

``RealtimeMeta`` holds the one ``epoch`` every worker uses on its frames (clients resynchronise when it changes, so it
must be the same in all of them). ``RealtimeSpool`` holds the occasional frame too big to travel inside a Postgres
notification (about 8 kB); the notification carries its id and the receivers read it from here.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, BigInteger, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from pufferblow.api.database.tables.declarative_base import Base


class RealtimeMeta(Base):
    __tablename__ = "realtime_meta"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(String(255), nullable=False)


class RealtimeSpool(Base):
    __tablename__ = "realtime_spool"

    spool_id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    frame: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
