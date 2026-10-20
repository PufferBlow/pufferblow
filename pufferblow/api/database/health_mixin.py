"""Persistence for the instance's own health history (see ``tables/health.py``)."""

from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import urlsplit
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.exc import OperationalError, ProgrammingError

from pufferblow.api.database.tables.activitypub import ActivityPubFollow
from pufferblow.api.database.tables.health import InstanceIncident, InstanceUptimeDay


def _aware(value: datetime | None) -> datetime | None:
    """SQLite hands back naive datetimes; treat them as UTC."""
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


class DatabaseHealthMixin:
    def record_health_check(self, day: str, ok: bool) -> None:
        """Count one check for ``day`` (``YYYY-MM-DD``), and whether it found everything working."""
        with self.database_session() as session:
            row = session.get(InstanceUptimeDay, day)
            if row is None:
                row = InstanceUptimeDay(day=day, checks=0, ok=0)
                session.add(row)
            row.checks = int(row.checks or 0) + 1
            if ok:
                row.ok = int(row.ok or 0) + 1
            session.commit()

    def list_uptime_days(self, since_day: str) -> list[dict]:
        """The days from ``since_day`` on, oldest first, as ``{day, checks, ok}``."""
        with self.database_session() as session:
            rows = session.execute(select(InstanceUptimeDay).where(InstanceUptimeDay.day >= since_day).order_by(InstanceUptimeDay.day)).scalars()
            return [{"day": r.day, "checks": int(r.checks), "ok": int(r.ok)} for r in rows]

    def open_health_incident(self, title: str, body: str = "") -> str:
        incident_id = str(uuid4())
        with self.database_session() as session:
            session.add(InstanceIncident(incident_id=incident_id, title=title[:200], body=body, state="investigating", started_at=datetime.now(timezone.utc)))
            session.commit()
        return incident_id

    def current_health_incident(self) -> dict | None:
        """The incident that is still open, if any."""
        with self.database_session() as session:
            row = session.execute(select(InstanceIncident).where(InstanceIncident.state != "resolved").order_by(InstanceIncident.started_at.desc())).scalars().first()
            return self._incident_dict(row) if row is not None else None

    def resolve_health_incident(self, incident_id: str) -> None:
        with self.database_session() as session:
            row = session.get(InstanceIncident, incident_id)
            if row is not None and row.state != "resolved":
                row.state = "resolved"
                row.ended_at = datetime.now(timezone.utc)
                session.commit()

    def list_health_incidents(self, limit: int = 20) -> list[dict]:
        """The most recent incidents, newest first."""
        with self.database_session() as session:
            rows = session.execute(select(InstanceIncident).order_by(InstanceIncident.started_at.desc()).limit(limit)).scalars()
            return [self._incident_dict(r) for r in rows]

    @staticmethod
    def _incident_dict(row: InstanceIncident) -> dict:
        started, ended = _aware(row.started_at), _aware(row.ended_at)
        return {
            "incident_id": row.incident_id,
            "title": row.title,
            "state": row.state,
            "body": row.body,
            "started_at": started.isoformat() if started else None,
            "ended_at": ended.isoformat() if ended else None,
        }

    def list_federation_hosts(self) -> list[dict]:
        """The instances this one is linked to by an accepted follow, as ``{host, follows, last_activity}``."""
        try:
            with self.database_session() as session:
                rows = session.execute(select(ActivityPubFollow).where(ActivityPubFollow.accepted.is_(True))).scalars().all()
        except (OperationalError, ProgrammingError):
            return []  # federation has never been used here, so its tables do not exist yet
        hosts: dict[str, dict] = {}
        for row in rows:
            host = urlsplit(row.remote_actor_uri).netloc.lower()
            if not host:
                continue
            entry = hosts.setdefault(host, {"host": host, "follows": 0, "last_activity": None})
            entry["follows"] += 1
            updated = _aware(row.updated_at)
            if updated and (entry["last_activity"] is None or updated.isoformat() > entry["last_activity"]):
                entry["last_activity"] = updated.isoformat()
        return sorted(hosts.values(), key=lambda h: h["host"])
