from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from sqlalchemy import String, Integer, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from pufferblow.api.database.tables.declarative_base import Base
from pufferblow.api.utils.current_date import date_in_gmt

class Server(Base):
    """Server table"""
    __tablename__ = "server"

    server_id: Mapped[str] = mapped_column(String, primary_key=True, nullable=False)
    server_name: Mapped[str] = mapped_column(String, nullable=False)
    host_port: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    avatar_url: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    banner_url: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    welcome_message: Mapped[str] = mapped_column(String, nullable=False)
    members_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    online_members: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Server stats
    stats_id: Mapped[str] = mapped_column(String, nullable=False)

    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=date_in_gmt, nullable=False
    )

    def __repr__(self) -> str:
        return (
            f"Server(server_id={self.server_id!r}, server_name={self.server_name!r}, "
            f"description={self.description!r}, avatar_url={self.avatar_url!r}, "
            f"banner_url={self.banner_url!r}, welcome_message={self.welcome_message!r}, "
            f"updated_at={self.updated_at!r}, created_at={self.created_at!r})"
        )
