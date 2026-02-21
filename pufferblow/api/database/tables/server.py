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
