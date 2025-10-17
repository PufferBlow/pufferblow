from sqlalchemy import (
    Column,
    String,
    Boolean,
    DateTime,
    ARRAY
)

# Declarative base class
from pufferblow.api.database.tables.declarative_base import Base

# Utils
from pufferblow.api.utils.current_date import date_in_gmt

class Users(Base):
    """ Users table """
    __tablename__ = "users"

    user_id                 =   Column(String, primary_key=True, nullable=False)
    username                =   Column(String, nullable=False)
    password                =   Column(String, nullable=False)
    avatar_url              =   Column(String, nullable=True)
    banner_url              =   Column(String, nullable=True)
    status                  =   Column(String, nullable=False)
    about                   =   Column(String, nullable=True)
    last_seen               =   Column(DateTime, default=date_in_gmt("%Y-%m-%d %H:%M:%S"), nullable=False)
    inbox_id                =   Column(String, nullable=False)
    origin_server           =   Column(String, nullable=False)
    joined_servers_ids      =   Column(ARRAY(String), default=[], nullable=False)
    auth_token              =   Column(String, nullable=False)
    auth_token_expire_time  =   Column(String, nullable=False)
    roles_ids               =   Column(ARRAY(String), default=[], nullable=False)
    updated_at              =   Column(DateTime, default=date_in_gmt("%Y-%m-%d %H:%M:%S"), nullable=True)
    created_at              =   Column(DateTime, default=date_in_gmt("%Y-%m-%d %H:%M:%S"), nullable=False)

    def __repr__(self) -> str:
        return f"Users(user_id={self.user_id!r}, username={self.username!r}, password={self.password!r}, avatar_url={self.avatar_url!r}, banner_url={self.banner_url!r}status={self.status!r}, last_seen={self.last_seen!r}, inbox_id={self.inbox_id!r}, origin_server={self.origin_server!r}, joined_servers_ids={self.joined_servers_ids!r}, auth_token={self.auth_token!r}, auth_token_expire_time={self.auth_token_expire_time!r}, roles_ids={self.roles_ids!r}, updated_at={self.updated_at!r}, created_at={self.created_at!r})"

