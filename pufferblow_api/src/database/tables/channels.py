from sqlalchemy import (
    Column,
    String,
    Boolean,
    DateTime,
    ARRAY
)

# Decrlarative base class
from pufferblow_api.src.database.tables.declarative_base import Base

# Utils
from pufferblow_api.src.utils.current_date import date_in_gmt

class Channels(Base):
    """ `Channels` table """
    __tablename__ = "channels"

    channel_id      =   Column(String, primary_key=True, nullable=False)
    channel_name    =   Column(String, nullable=False)
    messages_ids    =   Column(ARRAY(String), default=[])
    is_private      =   Column(Boolean, default=False)
    allowed_users   =   Column(ARRAY(String))
    created_at      =   Column(DateTime, default=date_in_gmt("%Y-%m-%d %H:%M:%S"))

    def __repr__(self):
        return f"Channels(channel_id={self.channel_id!r}, channel_name={self.channel_name!r}, messages_ids={self.messages_ids!r}, is_private={self.is_private!r}, allowed_users={self.allowed_users!r}, created_at={self.created_at!r})"
