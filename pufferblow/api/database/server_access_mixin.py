"""Persistence for the join mode, invitation codes, join requests and used assertions (``tables/server_access.py``)."""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.exc import IntegrityError

from pufferblow.api.database.tables.server_access import (
    FederationAssertionNonces,
    ServerAccess,
    ServerInvites,
    ServerJoinRequests,
)
from pufferblow.api.database.tables.users import Users

JOIN_MODES = ("open", "invite", "request")
DEFAULT_JOIN_MODE = "open"

#: Letters and digits that cannot be misread when a code is read out or typed (no 0/O, 1/I/l).
_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def new_invite_code() -> str:
    return "".join(secrets.choice(_CODE_ALPHABET) for _ in range(12))


class DatabaseServerAccessMixin:
    # ── join mode ──────────────────────────────────────────────

    def get_join_mode(self) -> str:
        """``open``, ``invite`` or ``request``. A server that never chose is ``invite`` if it was marked private, else ``open``."""
        with self.database_session() as session:
            row = session.get(ServerAccess, "global")
            if row is not None and row.join_mode in JOIN_MODES:
                return row.join_mode
        mode = DEFAULT_JOIN_MODE
        try:
            settings = self.get_server_settings()
            if settings is not None and bool(getattr(settings, "is_private", False)):
                mode = "invite"
        except Exception:
            # No settings table (the SQLite test database): nothing says it was private.
            pass
        return mode

    def set_join_mode(self, mode: str) -> None:
        if mode not in JOIN_MODES:
            raise ValueError(f"join mode must be one of {list(JOIN_MODES)}")
        with self.database_session() as session:
            row = session.get(ServerAccess, "global")
            if row is None:
                session.add(ServerAccess(access_id="global", join_mode=mode, updated_at=_now()))
            else:
                row.join_mode = mode
                row.updated_at = _now()
            session.commit()

    # ── invitation codes ───────────────────────────────────────

    def create_invite(self, *, created_by: str, note: str | None, max_uses: int | None, expires_at: datetime | None) -> dict:
        with self.database_session() as session:
            row = ServerInvites(code=new_invite_code(), created_by=str(created_by), note=(note or "").strip() or None, max_uses=max_uses, expires_at=expires_at)
            session.add(row)
            session.commit()
            session.refresh(row)
            return row.to_dict()

    def list_invites(self) -> list[dict]:
        with self.database_session() as session:
            rows = session.execute(select(ServerInvites).order_by(ServerInvites.created_at.desc())).scalars()
            return [row.to_dict() for row in rows]

    def revoke_invite(self, code: str) -> bool:
        with self.database_session() as session:
            result = session.execute(update(ServerInvites).where(ServerInvites.code == code, ServerInvites.revoked_at.is_(None)).values(revoked_at=_now()))
            session.commit()
            return bool(result.rowcount)

    def redeem_invite(self, code: str) -> bool:
        """Use one of a code's uses. One statement, so two people racing for the last use cannot both get it."""
        cleaned = (code or "").strip().upper().replace(" ", "").replace("-", "")
        if not cleaned:
            return False
        now = _now()
        with self.database_session() as session:
            result = session.execute(
                update(ServerInvites)
                .where(
                    ServerInvites.code == cleaned,
                    ServerInvites.revoked_at.is_(None),
                    or_(ServerInvites.expires_at.is_(None), ServerInvites.expires_at > now),
                    or_(ServerInvites.max_uses.is_(None), ServerInvites.uses < ServerInvites.max_uses),
                )
                .values(uses=ServerInvites.uses + 1)
            )
            session.commit()
            return bool(result.rowcount)

    # ── join requests ──────────────────────────────────────────

    def create_join_request(self, *, kind: str, handle: str, user_id: str | None = None, home_host: str | None = None, actor_uri: str | None = None, message: str | None = None) -> dict:
        with self.database_session() as session:
            row = ServerJoinRequests(
                request_id=str(uuid.uuid4()),
                kind=kind,
                user_id=str(user_id) if user_id else None,
                handle=handle,
                home_host=home_host,
                actor_uri=actor_uri,
                message=(message or "").strip()[:300] or None,
                status="pending",
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return row.to_dict()

    def list_join_requests(self, status: str | None = None, limit: int = 200) -> list[dict]:
        with self.database_session() as session:
            stmt = select(ServerJoinRequests).order_by(ServerJoinRequests.created_at.desc()).limit(limit)
            if status:
                stmt = stmt.where(ServerJoinRequests.status == status)
            return [row.to_dict() for row in session.execute(stmt).scalars()]

    def count_join_requests(self, status: str = "pending") -> int:
        with self.database_session() as session:
            return int(session.execute(select(func.count()).select_from(ServerJoinRequests).where(ServerJoinRequests.status == status)).scalar() or 0)

    def get_join_request(self, request_id: str) -> dict | None:
        with self.database_session() as session:
            row = session.get(ServerJoinRequests, request_id)
            return row.to_dict() if row is not None else None

    def latest_join_request_for(self, handle: str) -> dict | None:
        with self.database_session() as session:
            row = session.execute(select(ServerJoinRequests).where(ServerJoinRequests.handle == handle).order_by(ServerJoinRequests.created_at.desc()).limit(1)).scalar()
            return row.to_dict() if row is not None else None

    def decide_join_request(self, request_id: str, *, status: str, decided_by: str) -> dict | None:
        """Mark a pending request approved or denied. None if it is gone or was already decided."""
        with self.database_session() as session:
            result = session.execute(
                update(ServerJoinRequests)
                .where(ServerJoinRequests.request_id == request_id, ServerJoinRequests.status == "pending")
                .values(status=status, decided_by=str(decided_by), decided_at=_now())
            )
            session.commit()
            if not result.rowcount:
                return None
            row = session.get(ServerJoinRequests, request_id)
            return row.to_dict() if row is not None else None

    # ── membership of local accounts ───────────────────────────

    def set_membership_status(self, user_id: str, status: str) -> None:
        with self.database_session() as session:
            session.execute(update(Users).values(membership_status=status).where(Users.user_id == uuid.UUID(str(user_id))))
            session.commit()
        self._invalidate_user_cache(user_id)

    def user_ids_with_privilege(self, privilege_id: str) -> list[str]:
        """Local people whose roles include this privilege (the owner always counts)."""
        from pufferblow.api.database.tables.roles import Roles

        with self.database_session() as session:
            roles = session.execute(select(Roles.role_id, Roles.privileges_ids)).all()
        wanted = {role_id for role_id, privileges in roles if privilege_id in (privileges or [])}
        wanted.add("owner")
        return self.user_ids_with_roles(wanted)

    def user_ids_with_roles(self, role_ids: set[str]) -> list[str]:
        """Local people who hold at least one of these roles."""
        wanted = {r for r in role_ids if r}
        if not wanted:
            return []
        with self.database_session() as session:
            rows = session.execute(select(Users.user_id, Users.roles_ids)).all()
        return [str(user_id) for user_id, roles in rows if wanted.intersection(roles or [])]

    # ── used assertions ────────────────────────────────────────

    def consume_assertion_nonce(self, nonce: str, expires_at: datetime) -> bool:
        """Record an assertion as used. False if it already was (a replay)."""
        now = _now()
        with self.database_session() as session:
            session.execute(delete(FederationAssertionNonces).where(FederationAssertionNonces.expires_at < now - timedelta(minutes=5)))
            session.add(FederationAssertionNonces(nonce=nonce, expires_at=expires_at))
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                return False
            return True
