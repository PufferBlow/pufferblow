from sqlalchemy import (
    Column,
    String,
    Boolean,
    DateTime,
    ARRAY
)

# Decrlarative base class
from pufferblow.src.database.tables.declarative_base import Base

# Utils
from pufferblow.src.utils.current_date import date_in_gmt

class Users(Base):
    """ Users table """
    __tablename__ = "users"

    user_id                 =   Column(String, primary_key=True, nullable=False)
    username                =   Column(String, nullable=False)
    password                =   Column(String, nullable=False)
    status                  =   Column(String, nullable=False)
    last_seen               =   Column(DateTime, default=date_in_gmt("%Y-%m-%d %H:%M:%S"), nullable=False)
    conversations           =   Column(ARRAY(String), default=[], nullable=False)
    contacts                =   Column(ARRAY(String), default=[], nullable=False)
    joined_servers_ids      =   Column(ARRAY(String), default=[], nullable=False)
    auth_token              =   Column(String, nullable=False)
    auth_token_expire_time  =   Column(String, nullable=False)
    is_admin                =   Column(Boolean, default=False, nullable=False)
    is_owner                =   Column(Boolean, default=False, nullable=False)
    updated_at              =   Column(DateTime, default=date_in_gmt("%Y-%m-%d %H:%M:%S"), nullable=True)
    created_at              =   Column(DateTime, default=date_in_gmt("%Y-%m-%d %H:%M:%S"), nullable=False)

    def __repr__(self) -> str:
        return f"Users(user_id={self.user_id!r}, username={self.username!r}, password={self.password!r}, status={self.status!r}, last_seen={self.last_seen!r}, conversations={self.conversations!r}, contacts={self.contacts!r}, joined_servers_ids={self.joined_servers_ids!r}, auth_token={self.auth_token!r}, auth_token_expire_time={self.auth_token_expire_time!r}, is_admin={self.is_admin!r}, is_owner={self.is_owner!r}, updated_at={self.updated_at!r}, created_at={self.created_at!r})"

