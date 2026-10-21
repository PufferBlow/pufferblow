"""Persistence for channel categories and pins (see ``tables/channel_organization.py``)."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError

from pufferblow.api.database.tables.channel_organization import ChannelCategories, PinnedMessages
from pufferblow.api.database.tables.channels import Channels
from pufferblow.api.database.tables.messages import Messages
from pufferblow.api.database.tables.users import Users

#: A channel can hold this many pins; more than that and they stop being a short list worth reading.
MAX_PINS_PER_CHANNEL = 50


class CategoryNameTaken(Exception):
    """Another category already has that name."""


class DatabaseChannelOrgMixin:
    # ── categories ─────────────────────────────────────────────

    def list_categories(self) -> list[dict]:
        """Every category, in order."""
        with self.database_session() as session:
            rows = session.execute(select(ChannelCategories).order_by(ChannelCategories.position, ChannelCategories.name)).scalars()
            return [row.to_dict() for row in rows]

    def category_exists(self, category_id: str) -> bool:
        with self.database_session() as session:
            return session.get(ChannelCategories, category_id) is not None

    def create_category(self, name: str) -> dict:
        """Add a category at the end. Raises :class:`CategoryNameTaken` if the name is in use."""
        with self.database_session() as session:
            last = session.execute(select(func.max(ChannelCategories.position))).scalar()
            row = ChannelCategories(category_id=str(uuid4()), name=name, position=(last + 1) if last is not None else 0)
            session.add(row)
            try:
                session.commit()
            except IntegrityError as exc:
                session.rollback()
                raise CategoryNameTaken(name) from exc
            return row.to_dict()

    def update_category(self, category_id: str, name: str | None = None) -> dict | None:
        """Rename a category. None if there is no such category; raises :class:`CategoryNameTaken` on a clash."""
        with self.database_session() as session:
            row = session.get(ChannelCategories, category_id)
            if row is None:
                return None
            if name is not None:
                row.name = name
            try:
                session.commit()
            except IntegrityError as exc:
                session.rollback()
                raise CategoryNameTaken(name or "") from exc
            return row.to_dict()

    def delete_category(self, category_id: str) -> bool:
        """Remove a category; its channels stay, uncategorised. False if there was none."""
        with self.database_session() as session:
            row = session.get(ChannelCategories, category_id)
            if row is None:
                return False
            session.execute(update(Channels).where(Channels.category_id == category_id).values(category_id=None))
            session.delete(row)
            session.commit()
        return True

    def reorder_categories(self, category_ids: list[str]) -> list[dict]:
        """Put the named categories first, in the given order; any not named keep their relative order after them."""
        with self.database_session() as session:
            rows = list(session.execute(select(ChannelCategories).order_by(ChannelCategories.position, ChannelCategories.name)).scalars())
            by_id = {row.category_id: row for row in rows}
            named = [by_id[i] for i in dict.fromkeys(category_ids) if i in by_id]
            rest = [row for row in rows if row.category_id not in {r.category_id for r in named}]
            for index, row in enumerate([*named, *rest]):
                row.position = index
            session.commit()
            return [row.to_dict() for row in [*named, *rest]]

    # ── pins ───────────────────────────────────────────────────

    def pin_message(self, channel_id: str, message_id: str, pinned_by: str) -> str:
        """Pin a message. Returns ``"pinned"``, ``"already"`` or ``"full"`` (the channel is at its limit)."""
        with self.database_session() as session:
            if session.get(PinnedMessages, (channel_id, message_id)) is not None:
                return "already"
            count = session.execute(select(func.count()).select_from(PinnedMessages).where(PinnedMessages.channel_id == channel_id)).scalar() or 0
            if count >= MAX_PINS_PER_CHANNEL:
                return "full"
            session.add(PinnedMessages(channel_id=channel_id, message_id=message_id, pinned_by=pinned_by, pinned_at=datetime.now(timezone.utc)))
            session.commit()
        return "pinned"

    def unpin_message(self, channel_id: str, message_id: str) -> bool:
        with self.database_session() as session:
            row = session.get(PinnedMessages, (channel_id, message_id))
            if row is None:
                return False
            session.delete(row)
            session.commit()
        return True

    def list_pinned(self, channel_id: str) -> list[tuple[Messages, Users | None, dict]]:
        """A channel's pinned messages, newest pin first, each with who pinned it and when."""
        with self.database_session() as session:
            rows = (
                session.query(Messages, Users, PinnedMessages)
                .join(PinnedMessages, PinnedMessages.message_id == Messages.message_id)
                .join(Users, Messages.sender_id == Users.user_id, isouter=True)
                .filter(PinnedMessages.channel_id == channel_id, Messages.channel_id == channel_id)
                .order_by(PinnedMessages.pinned_at.desc())
                .all()
            )
            session.expunge_all()
        out = []
        for message, user, pin in rows:
            pinned_at = pin.pinned_at if pin.pinned_at.tzinfo else pin.pinned_at.replace(tzinfo=timezone.utc)
            out.append((message, user, {"pinned_by": pin.pinned_by, "pinned_at": pinned_at.isoformat()}))
        return out

    def drop_pins_for_message(self, message_id: str) -> None:
        """A deleted message cannot stay pinned."""
        with self.database_session() as session:
            session.execute(PinnedMessages.__table__.delete().where(PinnedMessages.message_id == message_id))
            session.commit()
