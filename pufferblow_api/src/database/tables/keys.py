from sqlalchemy import (
    Column,
    String,
    DateTime
)

# Decrlarative base class
from pufferblow_api.src.database.tables.declarative_base import Base

# Utils
from pufferblow_api.src.utils.current_date import date_in_gmt

class Keys(Base):
    """ `Keys` table """
    __tablename__ = "keys"

    key_value       =   Column(String, primary_key=True, nullable=False)
    associated_to   =   Column(String)
    user_id         =   Column(String, default=None)
    message_id      =   Column(String, default=None)
    created_at      =   Column(DateTime, default=date_in_gmt("%Y-%m-%d %H:%M:%S"))
    updated_at      =   Column(DateTime)

    def __repr__(self):
        return f"Keys(key_value={self.key_value!r}, associated_to={self.associated_to!r}, user_id={self.user_id!r}, message_id={self.message_id!r}, created_at={self.created_at!r}, updated_at={self.updated_at!r})"
