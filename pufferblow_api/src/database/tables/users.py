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

class Users(Base):
    """ Users table """
    __tablename__ = "users"

    user_id                 =   Column(String, primary_key=True, nullable=False)
    username                =   Column(String, nullable=False)
    password_hash           =   Column(String)
    status                  =   Column(String, nullable=False)
    last_seen               =   Column(DateTime, default=date_in_gmt("%Y-%m-%d %H:%M:%S"))
    conversations           =   Column(ARRAY(String), default=[])
    contacts                =   Column(ARRAY(String), default=[])
    created_at              =   Column(DateTime, default=date_in_gmt("%Y-%m-%d %H:%M:%S"))
    auth_token              =   Column(String)
    auth_token_expire_time  =   Column(String)
    updated_at              =   Column(DateTime, default=date_in_gmt("%Y-%m-%d %H:%M:%S"))
    is_admin                =   Column(Boolean, default=False)
    is_owner                =   Column(Boolean, default=False)

    def __repr__(self) -> str:
        return f"Users(user_id={self.user_id!r}, username={self.username!r}, password_hash={self.password_hash!r}, status={self.status!r}, last_seen={self.last_seen!r}, conversations={self.conversations!r}, contacts={self.contacts!r}, created_at={self.created_at!r}, auth_token={self.auth_token!r}, auth_token_expire_time={self.auth_token_expire_time!r}, updated_at={self.updated_at!r}, is_admin={self.is_admin!r}, is_owner={self.is_owner!r})"
