from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from pufferblow.api.database.tables.declarative_base import Base
from pufferblow.api.utils.current_date import date_in_gmt


class Server(Base):
    """Server table"""

    __tablename__ = "server"

    server_id: Mapped[str] = mapped_column(String, primary_key=True, nullable=False)
    server_name: Mapped[str] = mapped_column(String, nullable=False)
    host_port: Mapped[str] = mapped_column(String, nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(String, nullable=True)
    avatar_url: Mapped[str | None] = mapped_column(String, nullable=True)
    banner_url: Mapped[str | None] = mapped_column(String, nullable=True)
    # Appearance defaults — mirrors the Users table. See
    # ``pufferblow.api.utils.appearance``. The CLI ``pufferblow setup``
    # populates accent_color + avatar_seed on first server creation;
    # admins can swap to a custom image via the server settings tab.
    avatar_kind: Mapped[str] = mapped_column(
        String(16), nullable=False, default="identicon", server_default="identicon"
    )
    banner_kind: Mapped[str] = mapped_column(
        String(16), nullable=False, default="solid", server_default="solid"
    )
    accent_color: Mapped[str | None] = mapped_column(String(7), nullable=True)
    avatar_seed: Mapped[str | None] = mapped_column(String(64), nullable=True)
    welcome_message: Mapped[str] = mapped_column(String, nullable=False)
    is_private: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Server stats
    stats_id: Mapped[str] = mapped_column(String, nullable=False)

    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=date_in_gmt, nullable=False
    )

    def __repr__(self) -> str:
        """Repr special method."""
        return (
            f"Server(server_id={self.server_id!r}, server_name={self.server_name!r}, "
            f"description={self.description!r}, avatar_url={self.avatar_url!r}, "
            f"banner_url={self.banner_url!r}, welcome_message={self.welcome_message!r}, is_private={self.is_private!r}, "
            f"updated_at={self.updated_at!r}, created_at={self.created_at!r})"
        )

    def to_dict(self) -> dict:
        """Render as a client-facing dict.

        Used by the server-info route + the dashboard bootstrap. Includes
        the appearance fields so the client doesn't need a separate
        round trip to render the server icon and banner.
        """
        return {
            "server_id": self.server_id,
            "server_name": self.server_name,
            "host_port": self.host_port,
            "description": self.description,
            "avatar_url": self.avatar_url,
            "banner_url": self.banner_url,
            "avatar_kind": self.avatar_kind,
            "banner_kind": self.banner_kind,
            "accent_color": self.accent_color,
            "avatar_seed": self.avatar_seed,
            "welcome_message": self.welcome_message,
            "is_private": self.is_private,
            "stats_id": self.stats_id,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
