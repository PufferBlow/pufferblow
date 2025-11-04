from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List
from sqlalchemy import String, Boolean, DateTime, ARRAY
from sqlalchemy.orm import Mapped, mapped_column
from pufferblow.api.database.tables.declarative_base import Base
from pufferblow.api.utils.current_date import date_in_gmt


class Channels(Base):
    """Channels table"""
    __tablename__ = "channels"

    channel_id: Mapped[str] = mapped_column(String, primary_key=True, nullable=False)
    channel_name: Mapped[str] = mapped_column(String, nullable=False)
    channel_type: Mapped[str] = mapped_column(String, default="text")  # text, voice, mixed
    messages_ids: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String), default=list)
    is_private: Mapped[bool] = mapped_column(Boolean, default=False)
    allowed_users: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String), default=list)
    participant_ids: Mapped[Optional[List[str]]] = mapped_column(ARRAY(String), default=list)  # Active voice participants
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=lambda: date_in_gmt("%Y-%m-%d %H:%M:%S"),
        nullable=False,
    )

    def __repr__(self):
        return (
            f"Channels(channel_id={self.channel_id!r}, "
            f"channel_name={self.channel_name!r}, "
            f"messages_ids={self.messages_ids!r}, "
            f"is_private={self.is_private!r}, "
            f"allowed_users={self.allowed_users!r}, "
            f"created_at={self.created_at!r})"
        )
    
    def to_dict(self) -> dict:
        return {
            "channel_id"       :   self.channel_id,
            "channel_name"     :   self.channel_name,
            "channel_type"     :   self.channel_type,
            "messages_ids"     :   self.messages_ids,
            "is_private"       :   self.is_private,
            "allowed_users"    :   self.allowed_users,
            "participant_ids"  :   self.participant_ids,
            "created_at"       :   self.created_at
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
