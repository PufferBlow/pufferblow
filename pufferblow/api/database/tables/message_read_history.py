from sqlalchemy import (
    Column,
    String,
    ARRAY,
    DateTime
)

# Decrlarative base class
from pufferblow.api.database.tables.declarative_base import Base

# Utils
from pufferblow.api.utils.current_date import date_in_gmt

class MessageReadHistory(Base):
    """ `message_read_history` table """
    __tablename__ = "message_read_history"

    user_id                 =   Column(String, primary_key=True, nullable=False)
    viewed_messages_ids     =   Column(ARRAY(String), default=ARRAY(String), nullable=False)
    created_at              =   Column(DateTime, default=date_in_gmt(format="%Y-%m-%d %H:%M:%S"), nullable=False)
    updated_at              =   Column(DateTime, nullable=True)

    def __repr__(self) -> str:
        return f"MessageReadHistory(user_id={self.user_id!r}, viewed_messages_ids={self.viewed_messages_ids!r}, created_at={self.created_at!r}, updated_at={self.updated_at!r})"
