from sqlalchemy import (
    Column,
    String,
    DateTime
)

# Decrlarative base class
from pufferblow_api.src.database.tables.declarative_base import Base

# Utils
from pufferblow_api.src.utils.current_date import date_in_gmt

class Messages(Base):
    """ `messages` table """
    __tablename__ = "messages"

    message_id        =   Column(String, primary_key=True, nullable=False)
    hashed_message    =   Column(String, nullable=False)
    sender_user_id    =   Column(String, nullable=False)
    channel_id        =   Column(String, nullable=True)
    conversation_id   =   Column(String, nullable=True)
    sent_at         =   Column(DateTime, nullable=False, default=date_in_gmt(format="%Y-%m-%d %H:%M:%S"))

    def __repr__(self) -> str:
        return f"Messages(message_id={self.message_id!r}, hashed_message={self.hashed_message!r}, sender_user_id={self.sender_user_id!r}, channel_id={self.channel_id!r}, conversation_id={self.conversation_id!r}, sent_at={self.sent_at!r})"
