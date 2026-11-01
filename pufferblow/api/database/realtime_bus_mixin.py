"""Database side of the cross-worker realtime bus (PostgreSQL only; the SQLite test database keeps the in-process publisher)."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import delete, select, text

from pufferblow.api.database.tables.realtime_bus import RealtimeMeta, RealtimeSpool


#: How long a parked frame is kept. The workers read it within moments of it being sent.
SPOOL_KEEP_SECONDS = 60


class DatabaseRealtimeBusMixin:
    def _spool_cipher(self) -> Fernet:
        """What seals parked frames: a key made from the server's secret, which every worker has. A frame can carry
        a message's text, and messages are encrypted at rest, so it must not sit in a table in the clear."""
        secret = str(getattr(self.config, "JWT_SECRET", "") or "")
        key = hashlib.sha256(b"pufferblow:realtime-spool:" + secret.encode("utf-8")).digest()
        return Fernet(base64.urlsafe_b64encode(key))

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
        """Keep a frame too big for a notification, sealed, for the receivers to read by id."""
        sealed = self._spool_cipher().encrypt(json.dumps(frame, default=str).encode("utf-8")).decode("ascii")
        with self.database_session() as session:
            row = RealtimeSpool(frame={"v": 1, "sealed": sealed})
            session.add(row)
            session.flush()
            spool_id = int(row.spool_id)
            session.commit()
        self.purge_realtime_spool()
        return spool_id

    def read_spooled_realtime_frame(self, spool_id: int) -> dict | None:
        with self.database_session() as session:
            row = session.get(RealtimeSpool, int(spool_id))
            sealed = (row.frame or {}).get("sealed") if row is not None else None
        if not sealed:
            return None
        try:
            return json.loads(self._spool_cipher().decrypt(sealed.encode("ascii"), ttl=SPOOL_KEEP_SECONDS * 5))
        except (InvalidToken, ValueError):
            return None

    def purge_realtime_spool(self) -> int:
        """Remove parked frames older than they are ever read. Run after each new one and on a timer."""
        with self.database_session() as session:
            result = session.execute(delete(RealtimeSpool).where(RealtimeSpool.created_at < datetime.now(timezone.utc) - timedelta(seconds=SPOOL_KEEP_SECONDS)))
            session.commit()
            return int(result.rowcount or 0)
