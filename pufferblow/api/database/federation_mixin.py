"""Persistence for peer instances and the federation mode (see ``tables/peer_instances.py``)."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select

from pufferblow.api.database.tables.peer_instances import FederationSettings, PeerInstances
from pufferblow.api.federation.peers import DEFAULT_MODE, MODES, STATUSES, PeerError, effective_policy, validate_policy


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _iso(value: datetime | None) -> str | None:
    value = _aware(value)
    return value.isoformat() if value else None


def _peer_dict(row: PeerInstances) -> dict:
    return {
        "host": row.host,
        "status": row.status,
        "policy": effective_policy(row.status, row.policy_overrides),
        "policy_overrides": dict(row.policy_overrides or {}),
        "software": row.software,
        "version": row.version,
        "users": row.users_count,
        "contact": row.contact,
        "info_checked_at": _iso(row.info_checked_at),
        "first_seen": _iso(row.first_seen),
        "last_activity": _iso(row.last_activity),
        "last_delivery_at": _iso(row.last_delivery_at),
        "last_delivery_ok": row.last_delivery_ok,
        "latency_ms": row.latency_ms,
    }


class DatabaseFederationMixin:
    # ── mode ───────────────────────────────────────────────────

    def get_federation_mode(self) -> str:
        with self.database_session() as session:
            row = session.get(FederationSettings, "mode")
            return row.value if row is not None and row.value in MODES else DEFAULT_MODE

    def set_federation_mode(self, mode: str) -> None:
        if mode not in MODES:
            raise PeerError(f"mode must be one of {list(MODES)}.", "mode")
        with self.database_session() as session:
            row = session.get(FederationSettings, "mode")
            if row is None:
                session.add(FederationSettings(key="mode", value=mode))
            else:
                row.value = mode
            session.commit()

    # ── peers ──────────────────────────────────────────────────

    def get_peer(self, host: str) -> dict | None:
        with self.database_session() as session:
            row = session.get(PeerInstances, host)
            return _peer_dict(row) if row is not None else None

    def list_peers(self) -> list[dict]:
        """Every peer with how many accepted follows link us to it, by host."""
        with self.database_session() as session:
            rows = list(session.execute(select(PeerInstances).order_by(PeerInstances.host)).scalars())
            peers = [_peer_dict(row) for row in rows]
        follows = {h["host"]: h for h in self.list_federation_hosts()}
        for peer in peers:
            peer["follows"] = follows.get(peer["host"], {}).get("follows", 0)
        return peers

    def upsert_peer(self, host: str, status: str, added_by: str | None = None) -> tuple[dict, bool]:
        """Add a peer with a status, or return the one that exists unchanged. ``(peer, created)``."""
        if status not in STATUSES:
            raise PeerError(f"status must be one of {list(STATUSES)}.", "status")
        with self.database_session() as session:
            row = session.get(PeerInstances, host)
            created = row is None
            if row is None:
                row = PeerInstances(host=host, status=status, first_seen=datetime.now(timezone.utc), added_by=added_by)
                session.add(row)
                session.commit()
            return _peer_dict(row), created

    def set_peer_status(self, host: str, status: str) -> dict | None:
        if status not in STATUSES:
            raise PeerError(f"status must be one of {list(STATUSES)}.", "status")
        with self.database_session() as session:
            row = session.get(PeerInstances, host)
            if row is None:
                return None
            row.status = status
            session.commit()
            return _peer_dict(row)

    def set_peer_policy(self, host: str, changes: dict) -> dict | None:
        """Set some of the switches by hand. Resetting one to the status's own value drops the override."""
        clean = validate_policy(changes)
        with self.database_session() as session:
            row = session.get(PeerInstances, host)
            if row is None:
                return None
            overrides = dict(row.policy_overrides or {})
            overrides.update(clean)
            row.policy_overrides = overrides  # a new dict, so the JSON column notices the change
            session.commit()
            return _peer_dict(row)

    def delete_peer(self, host: str) -> bool:
        with self.database_session() as session:
            row = session.get(PeerInstances, host)
            if row is None:
                return False
            session.delete(row)
            session.commit()
        return True

    def touch_peer_activity(self, host: str) -> None:
        with self.database_session() as session:
            row = session.get(PeerInstances, host)
            if row is not None:
                row.last_activity = datetime.now(timezone.utc)
                session.commit()

    def record_peer_delivery(self, host: str, ok: bool, latency_ms: int | None = None) -> None:
        """Note a delivery attempt to a peer we know about. Latency is kept only for successes."""
        with self.database_session() as session:
            row = session.get(PeerInstances, host)
            if row is None:
                return
            row.last_delivery_at = datetime.now(timezone.utc)
            row.last_delivery_ok = bool(ok)
            if ok and latency_ms is not None:
                row.latency_ms = int(latency_ms)
            session.commit()

    def set_peer_info(self, host: str, *, software: str | None, version: str | None, users: int | None, contact: str | None = None) -> dict | None:
        """What the peer said about itself. A missing value keeps what we had."""
        with self.database_session() as session:
            row = session.get(PeerInstances, host)
            if row is None:
                return None
            if software:
                row.software = software[:64]
            if version:
                row.version = version[:64]
            if isinstance(users, int) and users >= 0:
                row.users_count = users
            if contact:
                row.contact = contact[:255]
            row.info_checked_at = datetime.now(timezone.utc)
            session.commit()
            return _peer_dict(row)
