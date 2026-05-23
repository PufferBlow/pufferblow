"""Friend graph manager — business logic over the `friendships` table.

The route layer (`api/routes/friends.py`) is a thin wrapper over this
class; the lifecycle invariants live here so they're testable
independently of FastAPI plumbing.

Invariants enforced:

  * No self-friend. A user can't friend themselves.
  * No duplicate pair, in either direction. If A already has a
    pending or accepted friendship with B, sending B → A returns
    the existing row instead of creating a second one.
  * Only the addressee can accept a pending request. Either side
    can cancel (delete the row).
  * `accept_request` only flips status when the actor is the
    addressee AND the current status is `pending`.

Status taxonomy is intentionally small for the v1.0 foundation —
just `pending` and `accepted`. `blocked` is a separate concern that
needs its own table (see the rationale in `tables/friendships.py`).
"""

from __future__ import annotations

import datetime
import uuid
from typing import TYPE_CHECKING

from loguru import logger
from sqlalchemy import and_, or_, select

from pufferblow.api.database.tables.friend_request_blocks import FriendRequestBlocks
from pufferblow.api.database.tables.friendships import Friendships

if TYPE_CHECKING:
    from pufferblow.api.database.database_handler import DatabaseHandler


# Lifecycle states. Stored as plain text in the DB; this constant is
# the source of truth and any new state added here must be reflected
# in the route layer's response validation.
STATUS_PENDING = "pending"
STATUS_ACCEPTED = "accepted"


class FriendsError(Exception):
    """Raised for any client-recoverable friend-graph error.

    Carries a `status_code` so the route layer can translate it to
    the right HTTP status without re-matching exception classes.
    """

    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


class FriendsManager:
    """Friend-graph lifecycle: send, accept, cancel, list."""

    def __init__(self, database_handler: "DatabaseHandler") -> None:
        self.database_handler = database_handler

    # ── Internal helpers ──────────────────────────────────────────

    def _find_pair(
        self, session, user_a: str, user_b: str
    ) -> Friendships | None:
        """Return the friendship row between two users (any direction).

        We don't normalize the pair on insert (`requester_id` /
        `addressee_id` keep their original roles for provenance), so
        the lookup walks both directions in one query.
        """
        a = self._normalize_user_id(user_a)
        b = self._normalize_user_id(user_b)
        stmt = select(Friendships).where(
            or_(
                and_(
                    Friendships.requester_id == a,
                    Friendships.addressee_id == b,
                ),
                and_(
                    Friendships.requester_id == b,
                    Friendships.addressee_id == a,
                ),
            )
        )
        return session.execute(stmt).scalar_one_or_none()

    def _normalize_user_id(self, value):
        """Coerce a user_id input to the right type for the engine.

        Postgres uses native UUID; SQLite (the test harness) uses
        String(36). The columns declare both via `with_variant`, so
        callers can pass a string in either case — we only need to
        produce a `uuid.UUID` on Postgres.
        """
        is_sqlite = str(self.database_handler.database_engine.url).startswith(
            "sqlite://"
        )
        if is_sqlite:
            return str(value)
        if isinstance(value, uuid.UUID):
            return value
        try:
            return uuid.UUID(str(value))
        except (TypeError, ValueError):
            # Bubble up as a 400 so the route can return a clean
            # "invalid user_id" instead of a 500.
            raise FriendsError(f"Invalid user_id: {value!r}", status_code=400)

    # ── Lifecycle ────────────────────────────────────────────────

    def send_request(
        self, *, requester_id: str, addressee_id: str
    ) -> Friendships:
        """Send a friend request from `requester` to `addressee`.

        Returns the resulting friendship row. If a row already exists
        for the pair (either direction, either status), it's returned
        unchanged — the operation is idempotent and the caller can
        check `.status` to know whether anything actually happened.

        Raises:
          * `FriendsError(400)` on self-friend or invalid id.
          * `FriendsError(403)` when the addressee has blocked
            incoming requests from the requester. We do NOT reveal
            "you are blocked" to keep the failure indistinguishable
            from other server-side rejections; the wire message
            simply says the request was rejected by the recipient.
        """
        if str(requester_id) == str(addressee_id):
            raise FriendsError("You can't friend yourself.", status_code=400)

        with self.database_handler.database_session() as session:
            # Block check — the addressee may have blocked incoming
            # requests from this requester. Single point lookup on
            # the composite PK; cheap on the hot path.
            blocked_row = session.execute(
                select(FriendRequestBlocks).where(
                    FriendRequestBlocks.blocker_id
                    == self._normalize_user_id(addressee_id),
                    FriendRequestBlocks.blocked_id
                    == self._normalize_user_id(requester_id),
                )
            ).scalar_one_or_none()
            if blocked_row is not None:
                # Deliberately vague — see docstring above.
                raise FriendsError(
                    "This user is not accepting friend requests.",
                    status_code=403,
                )

            existing = self._find_pair(session, requester_id, addressee_id)
            if existing is not None:
                # Already on the graph in some form. Return as-is —
                # this matches the "send a request you already sent"
                # idempotency contract used by most messaging apps.
                return existing

            row = Friendships(
                friendship_id=str(uuid.uuid4()),
                requester_id=self._normalize_user_id(requester_id),
                addressee_id=self._normalize_user_id(addressee_id),
                status=STATUS_PENDING,
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            logger.info(
                "Friend request sent: {req} -> {ad} (friendship_id={fid})",
                req=requester_id,
                ad=addressee_id,
                fid=row.friendship_id,
            )
            return row

    def accept_request(
        self, *, friendship_id: str, actor_user_id: str
    ) -> Friendships:
        """Flip a pending request to accepted.

        Only the addressee can accept. Anyone else (including the
        original requester) gets a 403.

        Raises `FriendsError(404)` if the row doesn't exist,
        `FriendsError(403)` if the actor isn't the addressee,
        `FriendsError(409)` if the row is not in `pending`.
        """
        with self.database_handler.database_session() as session:
            row = session.execute(
                select(Friendships).where(
                    Friendships.friendship_id == friendship_id
                )
            ).scalar_one_or_none()
            if row is None:
                raise FriendsError("Friendship not found.", status_code=404)
            if str(row.addressee_id) != str(actor_user_id):
                raise FriendsError(
                    "Only the recipient can accept this request.",
                    status_code=403,
                )
            if row.status != STATUS_PENDING:
                raise FriendsError(
                    f"This request is already {row.status}.", status_code=409
                )

            row.status = STATUS_ACCEPTED
            row.updated_at = datetime.datetime.now(datetime.timezone.utc)
            session.add(row)
            session.commit()
            session.refresh(row)
            logger.info(
                "Friend request accepted: friendship_id={fid} by user={u}",
                fid=friendship_id,
                u=actor_user_id,
            )
            return row

    def delete_relationship(
        self, *, friendship_id: str, actor_user_id: str
    ) -> bool:
        """Cancel a pending request OR unfriend an accepted relationship.

        Either side of the pair can call this; the requester
        "cancels" a pending row, the addressee "rejects" it, and
        either side "unfriends" an accepted row. Returns True iff a
        row was actually deleted.

        Raises `FriendsError(404)` if the row doesn't exist,
        `FriendsError(403)` if the actor isn't part of the pair.
        """
        with self.database_handler.database_session() as session:
            row = session.execute(
                select(Friendships).where(
                    Friendships.friendship_id == friendship_id
                )
            ).scalar_one_or_none()
            if row is None:
                raise FriendsError("Friendship not found.", status_code=404)
            if str(row.requester_id) != str(actor_user_id) and str(
                row.addressee_id
            ) != str(actor_user_id):
                raise FriendsError(
                    "You aren't a member of this friendship.",
                    status_code=403,
                )

            session.delete(row)
            session.commit()
            logger.info(
                "Friendship deleted: friendship_id={fid} by user={u}",
                fid=friendship_id,
                u=actor_user_id,
            )
            return True

    def unfriend(
        self, *, actor_user_id: str, other_user_id: str
    ) -> bool:
        """Delete the accepted friendship between two users (by other-side id).

        Convenience over `delete_relationship` for the
        `DELETE /api/v1/friends/{user_id}` shape — the client knows
        the other person's user_id but not the friendship row id.
        Returns True iff a row was deleted; False if there was no
        accepted relationship to remove (idempotent).
        """
        with self.database_handler.database_session() as session:
            row = self._find_pair(session, actor_user_id, other_user_id)
            if row is None or row.status != STATUS_ACCEPTED:
                return False
            session.delete(row)
            session.commit()
            logger.info(
                "Unfriend: actor={a} other={o}",
                a=actor_user_id,
                o=other_user_id,
            )
            return True

    # ── Reads ────────────────────────────────────────────────────

    def list_friends(self, *, user_id: str) -> list[dict]:
        """Return every accepted friend for `user_id`.

        Result rows surface BOTH the friendship row and the other
        side of the pair, so the client doesn't need a follow-up
        lookup to render a name / avatar. The 'other_user_id' field
        is whichever side of the pair isn't `user_id`.
        """
        normalized = self._normalize_user_id(user_id)
        with self.database_handler.database_session() as session:
            rows = session.execute(
                select(Friendships).where(
                    Friendships.status == STATUS_ACCEPTED,
                    or_(
                        Friendships.requester_id == normalized,
                        Friendships.addressee_id == normalized,
                    ),
                )
            ).scalars().all()

            results: list[dict] = []
            for row in rows:
                other_user_id = (
                    str(row.addressee_id)
                    if str(row.requester_id) == str(user_id)
                    else str(row.requester_id)
                )
                results.append({
                    **row.to_dict(),
                    "other_user_id": other_user_id,
                })
            return results

    def list_pending(self, *, user_id: str) -> dict:
        """Return the user's incoming + outgoing pending requests.

        Split by direction so the UI can label each section
        ("Sent" vs "Received") without re-deriving from
        requester/addressee on the client.
        """
        normalized = self._normalize_user_id(user_id)
        with self.database_handler.database_session() as session:
            incoming = session.execute(
                select(Friendships).where(
                    Friendships.status == STATUS_PENDING,
                    Friendships.addressee_id == normalized,
                )
            ).scalars().all()
            outgoing = session.execute(
                select(Friendships).where(
                    Friendships.status == STATUS_PENDING,
                    Friendships.requester_id == normalized,
                )
            ).scalars().all()

        def _shape(row: Friendships, *, other_user_id: str) -> dict:
            return {**row.to_dict(), "other_user_id": other_user_id}

        return {
            "incoming": [
                _shape(row, other_user_id=str(row.requester_id))
                for row in incoming
            ],
            "outgoing": [
                _shape(row, other_user_id=str(row.addressee_id))
                for row in outgoing
            ],
        }

    # ── Block list ───────────────────────────────────────────────

    def block_user(
        self, *, blocker_id: str, blocked_id: str
    ) -> FriendRequestBlocks:
        """Block incoming friend requests from `blocked_id` toward `blocker_id`.

        Side effects on existing graph state:
          * Any pending friend request from `blocked_id` → `blocker_id`
            is DELETED in the same transaction so the blocker isn't
            left with a stale inbox row.
          * An ACCEPTED friendship is left intact — see the rationale
            in the table docstring. To end the friendship the user
            calls `unfriend` separately.

        Idempotent — re-blocking returns the existing row unchanged.
        """
        if str(blocker_id) == str(blocked_id):
            raise FriendsError(
                "You can't block yourself.", status_code=400
            )

        blocker = self._normalize_user_id(blocker_id)
        blocked = self._normalize_user_id(blocked_id)
        with self.database_handler.database_session() as session:
            existing = session.execute(
                select(FriendRequestBlocks).where(
                    FriendRequestBlocks.blocker_id == blocker,
                    FriendRequestBlocks.blocked_id == blocked,
                )
            ).scalar_one_or_none()
            if existing is not None:
                return existing

            row = FriendRequestBlocks(
                blocker_id=blocker,
                blocked_id=blocked,
            )
            session.add(row)

            # Delete any pending request from blocked → blocker so the
            # blocker's inbox reflects the block immediately. Pending
            # requests in the OTHER direction (blocker → blocked) are
            # the blocker's own outgoing — left alone; they can
            # cancel via the normal delete path if they want to.
            pending = session.execute(
                select(Friendships).where(
                    Friendships.requester_id == blocked,
                    Friendships.addressee_id == blocker,
                    Friendships.status == STATUS_PENDING,
                )
            ).scalar_one_or_none()
            if pending is not None:
                session.delete(pending)

            session.commit()
            session.refresh(row)
            logger.info(
                "Friend-request block: blocker={a} blocked={b}",
                a=blocker_id,
                b=blocked_id,
            )
            return row

    def unblock_user(
        self, *, blocker_id: str, blocked_id: str
    ) -> bool:
        """Remove a friend-request block.

        Returns True iff a row was deleted; False if there was no
        block to remove (idempotent).
        """
        with self.database_handler.database_session() as session:
            row = session.execute(
                select(FriendRequestBlocks).where(
                    FriendRequestBlocks.blocker_id
                    == self._normalize_user_id(blocker_id),
                    FriendRequestBlocks.blocked_id
                    == self._normalize_user_id(blocked_id),
                )
            ).scalar_one_or_none()
            if row is None:
                return False
            session.delete(row)
            session.commit()
            logger.info(
                "Friend-request unblock: blocker={a} blocked={b}",
                a=blocker_id,
                b=blocked_id,
            )
            return True

    def list_blocks(self, *, blocker_id: str) -> list[dict]:
        """Return every user the actor has blocked from sending requests."""
        normalized = self._normalize_user_id(blocker_id)
        with self.database_handler.database_session() as session:
            rows = session.execute(
                select(FriendRequestBlocks).where(
                    FriendRequestBlocks.blocker_id == normalized
                )
            ).scalars().all()
        return [row.to_dict() for row in rows]
