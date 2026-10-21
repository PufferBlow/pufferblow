from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import ARRAY, JSON, Boolean, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from pufferblow.api.database.tables.declarative_base import Base
class Channels(Base):
    """Channels table"""

    __tablename__ = "channels"

    channel_id: Mapped[str] = mapped_column(String, primary_key=True, nullable=False)
    channel_name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    channel_type: Mapped[str] = mapped_column(
        String(24), default="text", index=True
    )  # text, voice, mixed
    messages_ids: Mapped[list[str] | None] = mapped_column(
        ARRAY(String).with_variant(JSON(), "sqlite"), default=list
    )
    is_private: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    allowed_users: Mapped[list[str] | None] = mapped_column(
        ARRAY(String).with_variant(JSON(), "sqlite"), default=list
    )
    participant_ids: Mapped[list[str] | None] = mapped_column(
        ARRAY(String).with_variant(JSON(), "sqlite"), default=list
    )  # Active voice participants
    # Organisation: the category it sits in (see tables/channel_organization.py), its order within
    # that category, and one line about what it is for. All optional for a channel.
    category_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    position: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    topic: Mapped[str | None] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self):
        """Repr special method."""
        return (
            f"Channels(channel_id={self.channel_id!r}, "
            f"channel_name={self.channel_name!r}, "
            f"messages_ids={self.messages_ids!r}, "
            f"is_private={self.is_private!r}, "
            f"allowed_users={self.allowed_users!r}, "
            f"created_at={self.created_at!r})"
        )

    def to_dict(self) -> dict:
        """To dict."""
        return {
            "channel_id": self.channel_id,
            "channel_name": self.channel_name,
            "channel_type": self.channel_type,
            "messages_ids": self.messages_ids,
            "is_private": self.is_private,
            "allowed_users": self.allowed_users,
            "participant_ids": self.participant_ids,
            "category_id": self.category_id,
            "position": self.position,
            "topic": self.topic,
            "created_at": self.created_at,
        }


# from sqlalchemy import (
#     Column,
#     String,
#     Boolean,
#     DateTime,
#     ARRAY
# )

# # Decrlarative base class
# from pufferblow.api.database.tables.declarative_base import Base

# # Utils
# from pufferblow.api.utils.current_date import date_in_gmt

# class Channels(Base):
#     """ `Channels` table """
#     __tablename__ = "channels"

#     channel_id      =   Column(String, primary_key=True, nullable=False)
#     channel_name    =   Column(String, nullable=False)
#     messages_ids    =   Column(ARRAY(String), default=[])
#     is_private      =   Column(Boolean, default=False)
#     allowed_users   =   Column(ARRAY(String))
#     created_at      =   Column(DateTime, default=date_in_gmt("%Y-%m-%d %H:%M:%S"))

#     def __repr__(self):
#         return f"Channels(channel_id={self.channel_id!r}, channel_name={self.channel_name!r}, messages_ids={self.messages_ids!r}, is_private={self.is_private!r}, allowed_users={self.allowed_users!r}, created_at={self.created_at!r})"
