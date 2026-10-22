"""Who is in each direct-message conversation.

A conversation id is a hash of the two people's actor addresses, so it cannot be turned back into
people. Until the second person has replied, the messages alone name only the sender, which left a
conversation the viewer started out of their conversation list (and its history unreachable from the
sidebar). This table keeps both participants from the first message.
"""

from __future__ import annotations

from sqlalchemy import String, select
from sqlalchemy.orm import Mapped, mapped_column

from pufferblow.api.database.tables.declarative_base import Base
from pufferblow.api.database.tables.users import Users


class DmConversationMembers(Base):
    """One participant of one DM conversation."""

    __tablename__ = "dm_conversation_members"

    conversation_id: Mapped[str] = mapped_column(String(80), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), primary_key=True)


class DatabaseDmMembersMixin:
    def record_dm_members(self, conversation_id: str, user_ids: list[str | None]) -> None:
        """Remember who is in a conversation. Safe to call on every message."""
        wanted = {str(u) for u in user_ids if u}
        if not wanted:
            return
        with self.database_session() as session:
            have = set(session.execute(select(DmConversationMembers.user_id).where(DmConversationMembers.conversation_id == conversation_id)).scalars())
            for user_id in wanted - have:
                session.add(DmConversationMembers(conversation_id=conversation_id, user_id=user_id))
            session.commit()

    def get_dm_other_member(self, conversation_id: str, viewer_user_id: str) -> str | None:
        """The other person in a conversation, if it is known."""
        with self.database_session() as session:
            row = session.execute(
                select(DmConversationMembers.user_id).where(
                    DmConversationMembers.conversation_id == conversation_id, DmConversationMembers.user_id != str(viewer_user_id)
                )
            ).first()
            return str(row[0]) if row else None

    def local_user_ids(self, limit: int = 5000) -> list[str]:
        """Ids of the users on this instance (for recovering a conversation's peer by its hash)."""
        with self.database_session() as session:
            return [str(u) for u in session.execute(select(Users.user_id).limit(limit)).scalars()]
