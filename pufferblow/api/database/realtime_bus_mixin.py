"""Database side of the cross-worker realtime bus (PostgreSQL only; the SQLite test database keeps the in-process publisher)."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select, text

from pufferblow.api.database.tables.realtime_bus import RealtimeMeta, RealtimeSpool


class DatabaseRealtimeBusMixin:
    def next_channel_event_seq(self, channel_id: str) -> int:
        """The next sequence number of a channel's events, taken atomically so every worker agrees on the order."""
        with self.database_session() as session:
            value = session.execute(
                text(
                    "INSERT INTO channel_event_seq (channel_id, high_water) VALUES (:c, 1) "
                    "ON CONFLICT (channel_id) DO UPDATE SET high_water = channel_event_seq.high_water + 1 "
                    "RETURNING high_water"
                ),
                {"c": str(channel_id)},
            ).scalar_one()
            session.commit()
        return int(value)

    def get_realtime_epoch(self) -> str:
        """The epoch all workers put on their frames: made once, then shared (clients resynchronise when it changes)."""
        with self.database_session() as session:
            session.execute(
                text("INSERT INTO realtime_meta (key, value) VALUES ('epoch', :v) ON CONFLICT (key) DO NOTHING"),
                {"v": secrets.token_urlsafe(8)},
            )
            session.commit()
            return session.execute(select(RealtimeMeta.value).where(RealtimeMeta.key == "epoch")).scalar_one()

    def notify_realtime(self, channel: str, payload: str) -> None:
        """Send a notification to every worker that is listening on ``channel`` (delivered when this commits)."""
        with self.database_session() as session:
            session.execute(text("SELECT pg_notify(:c, :p)"), {"c": channel, "p": payload})
            session.commit()

    def spool_realtime_frame(self, frame: dict) -> int:
        """Keep a frame too big for a notification, for the receivers to read by id. Old ones are cleared as new ones come."""
        with self.database_session() as session:
            row = RealtimeSpool(frame=frame)
            session.add(row)
            session.flush()
            spool_id = int(row.spool_id)
            session.execute(delete(RealtimeSpool).where(RealtimeSpool.created_at < datetime.now(timezone.utc) - timedelta(minutes=2)))
            session.commit()
        return spool_id

    def read_spooled_realtime_frame(self, spool_id: int) -> dict | None:
        with self.database_session() as session:
            row = session.get(RealtimeSpool, int(spool_id))
            return dict(row.frame) if row is not None else None
