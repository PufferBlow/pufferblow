"""Persistence for identity keys (see ``tables/identity_keys.py``)."""

from __future__ import annotations

from sqlalchemy import func, select

from pufferblow.api.database.tables.identity_keys import IdentityKeys
from pufferblow.api.identity.keys import MAX_KEYS_PER_USER


class IdentityKeyLimit(Exception):
    """The person already has the most keys they may."""


class IdentityKeyOwnedByAnother(Exception):
    """That key is already registered to someone else."""


class DatabaseIdentityKeysMixin:
    def register_identity_key(self, user_id: str, key_id: str, public_key_json: str, label: str | None) -> tuple[dict, bool]:
        """Register a key for a person. ``(key, created)``; registering the same key again changes nothing.

        Raises :class:`IdentityKeyOwnedByAnother` if another person holds it, and :class:`IdentityKeyLimit`
        at the per-person maximum.
        """
        with self.database_session() as session:
            existing = session.get(IdentityKeys, key_id)
            if existing is not None:
                if existing.user_id != user_id:
                    raise IdentityKeyOwnedByAnother()
                return existing.to_dict(), False
            count = session.execute(select(func.count()).select_from(IdentityKeys).where(IdentityKeys.user_id == user_id)).scalar() or 0
            if count >= MAX_KEYS_PER_USER:
                raise IdentityKeyLimit()
            row = IdentityKeys(key_id=key_id, user_id=user_id, public_key=public_key_json, label=(label or None))
            session.add(row)
            session.commit()
            return row.to_dict(), True

    def list_identity_keys(self, user_id: str) -> list[dict]:
        with self.database_session() as session:
            rows = session.execute(select(IdentityKeys).where(IdentityKeys.user_id == user_id).order_by(IdentityKeys.created_at)).scalars()
            return [row.to_dict() for row in rows]

    def delete_identity_key(self, user_id: str, key_id: str) -> bool:
        """Remove one of the person's own keys. False if they have no such key."""
        with self.database_session() as session:
            row = session.get(IdentityKeys, key_id)
            if row is None or row.user_id != user_id:
                return False
            session.delete(row)
            session.commit()
            return True
