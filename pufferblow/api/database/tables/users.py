from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import JSON, DateTime, String
from sqlalchemy.dialects.postgresql import UUID as SA_UUID
from sqlalchemy.orm import Mapped, mapped_column

# Base
from pufferblow.api.database.tables.declarative_base import Base


class Users(Base):
    """SQLAlchemy model representing the Users table.

    This table stores user account information including authentication
    details, profile data, and server relationships.

    Attributes:
        user_id (Mapped[UUID]): Primary key, unique user identifier.
        username (Mapped[str]): Unique username for the user.
        password (Mapped[str]): Hashed password for authentication.
        about (Mapped[Optional[str]]): User's bio/description.
        avatar_url (Mapped[Optional[str]]): URL to user's avatar image.
        banner_url (Mapped[Optional[str]]): URL to user's banner image.
        inbox_id (Mapped[Optional[UUID]]): ID of user's inbox channel.
        origin_server (Mapped[str]): Origin server identifier.
        status (Mapped[str]): User's current status (online/offline).
        roles_ids (Mapped[List[str]]): List of role IDs assigned to user.
        last_seen (Mapped[Optional[datetime]]): Last seen timestamp.
        joined_servers_ids (Mapped[List[str]]): Server IDs user has joined.
        auth_token (Mapped[str]): Encrypted auth token for sessions.
        raw_auth_token (Optional[str]): Unencrypted auth token (not mapped).
        auth_token_expire_time (Mapped[Optional[datetime]]): Token expiration.
        created_at (Mapped[datetime]): Account creation timestamp.
        updated_at (Mapped[datetime]): Last update timestamp.

    Example:
        >>> user = Users(username="example", password="hashed")
        >>> print(user.username)
        'example'
    """

    __tablename__ = "users"
    __allow_unmapped__ = True

    user_id: Mapped[UUID] = mapped_column(
        SA_UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    username: Mapped[str] = mapped_column(String, nullable=False)
    password: Mapped[str] = mapped_column(String, default="")
    about: Mapped[str | None] = mapped_column(String, nullable=True)
    avatar_url: Mapped[str | None] = mapped_column(String, nullable=True)
    banner_url: Mapped[str | None] = mapped_column(String, nullable=True)
    inbox_id: Mapped[UUID | None] = mapped_column(
        SA_UUID(as_uuid=True), nullable=True
    )
    origin_server: Mapped[str] = mapped_column(String, default="")
    status: Mapped[str] = mapped_column(String, default="offline")
    roles_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    joined_servers_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    auth_token: Mapped[str] = mapped_column(String, default="")
    raw_auth_token: str | None = None
    auth_token_expire_time: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.now(timezone.utc),
        onupdate=datetime.now(timezone.utc),
    )

    def __repr__(self) -> str:
        return (
            f"Users(user_id={self.user_id!r}, username={self.username!r}, "
            f"password={self.password!r}, avatar_url={self.avatar_url!r}, "
            f"banner_url={self.banner_url!r}, inbox_id={self.inbox_id!r}, "
            f"origin_server={self.origin_server!r}, status={self.status!r}, "
            f"roles_ids={self.roles_ids!r}, last_seen={self.last_seen!r}, "
            f"joined_servers_ids={self.joined_servers_ids!r}, auth_token={self.auth_token!r}, "
            f"auth_token_expire_time={self.auth_token_expire_time!r}, created_at={self.created_at!r}, "
            f"updated_at={self.updated_at!r})"
        )

    def to_dict(self) -> dict:
        return {
            "user_id": self.user_id,
            "username": self.username,
            "password": self.password,
            "about": self.about,
            "avatar_url": self.avatar_url,
            "banner_url": self.banner_url,
            "status": self.status,
            "origin_server": self.origin_server,
            "inbox_id": self.inbox_id,
            "roles_ids": self.roles_ids,
            "last_seen": self.last_seen,
            "joined_servers_ids": self.joined_servers_ids,
            "auth_token": self.auth_token,
            "auth_token_expire_time": self.auth_token_expire_time,
            "raw_auth_token": self.raw_auth_token,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
