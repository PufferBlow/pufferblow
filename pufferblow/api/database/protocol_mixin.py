"""Persistence for command idempotency and bot identities."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.exc import IntegrityError

from pufferblow.api.database.tables.bots import Bots
from pufferblow.api.database.tables.command_idempotency import CommandIdempotency

#: A ``pending`` reservation older than this belongs to a command whose process died.
PENDING_TAKEOVER_AFTER = timedelta(seconds=60)


def _aware(value: datetime) -> datetime:
    """SQLite hands back naive datetimes; treat them as UTC."""
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


class DatabaseProtocolMixin:
    # ── idempotency ────────────────────────────────────────────

    def reserve_idempotency_key(self, principal_id: str, operation: str, key: str) -> tuple[str, dict | None]:
        """Claim a key before running a mutation.

        Returns ``(state, stored_result)`` where state is:

        * ``"reserved"``   this caller owns the key and must run the command.
        * ``"completed"``  a previous run finished; ``stored_result`` is its result.
        * ``"in_progress"`` another run is still going; try again shortly.
        """
        now = datetime.now(timezone.utc)
        with self.database_session() as session:
            row = session.get(CommandIdempotency, (principal_id, operation, key))
            if row is None:
                session.add(
                    CommandIdempotency(
                        principal_id=principal_id, operation=operation, key=key,
                        status="pending", created_at=now, updated_at=now,
                    )
                )
                try:
                    session.commit()
                    return "reserved", None
                except IntegrityError:
                    # Lost a race with a concurrent identical command.
                    session.rollback()
                    row = session.get(CommandIdempotency, (principal_id, operation, key))
                    if row is None:
                        return "in_progress", None

            if row.status == "completed":
                return "completed", row.result

            if now - _aware(row.updated_at) > PENDING_TAKEOVER_AFTER:
                row.updated_at = now
                session.commit()
                return "reserved", None
            return "in_progress", None

    def complete_idempotency_key(self, principal_id: str, operation: str, key: str, result: dict) -> None:
        with self.database_session() as session:
            row = session.get(CommandIdempotency, (principal_id, operation, key))
            if row is None:
                return
            row.status = "completed"
            row.result = result
            row.updated_at = datetime.now(timezone.utc)
            session.commit()

    def release_idempotency_key(self, principal_id: str, operation: str, key: str) -> None:
        """Forget a reservation whose command failed, so the client can retry for real."""
        with self.database_session() as session:
            row = session.get(CommandIdempotency, (principal_id, operation, key))
            if row is not None and row.status == "pending":
                session.delete(row)
                session.commit()

    def purge_idempotency_keys(self, older_than: timedelta = timedelta(hours=24)) -> int:
        cutoff = datetime.now(timezone.utc) - older_than
        with self.database_session() as session:
            deleted = session.query(CommandIdempotency).filter(CommandIdempotency.created_at < cutoff).delete()
            session.commit()
            return int(deleted or 0)

    # ── bots ───────────────────────────────────────────────────

    def insert_bot(self, bot: Bots) -> None:
        with self.database_session() as session:
            session.add(bot)
            session.commit()

    def get_bot_by_prefix(self, token_prefix: str) -> Bots | None:
        with self.database_session() as session:
            row = session.query(Bots).filter(Bots.token_prefix == token_prefix).first()
            if row is not None:
                session.expunge(row)
            return row

    def get_bot(self, bot_id: str) -> Bots | None:
        with self.database_session() as session:
            row = session.get(Bots, bot_id)
            if row is not None:
                session.expunge(row)
            return row

    def revoke_bot(self, bot_id: str) -> bool:
        with self.database_session() as session:
            row = session.get(Bots, bot_id)
            if row is None or row.revoked_at is not None:
                return False
            row.revoked_at = datetime.now(timezone.utc)
            row.enabled = False
            session.commit()
            return True
