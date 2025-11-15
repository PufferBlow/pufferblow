from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.dialects.postgresql import UUID as SA_UUID
from sqlalchemy.orm import Mapped, mapped_column

from pufferblow.api.database.tables.declarative_base import Base


class ServerStickers(Base):
    """Server stickers catalog table"""

    __tablename__ = "server_stickers"

    sticker_id: Mapped[str] = mapped_column(String, primary_key=True, nullable=False)
    sticker_url: Mapped[str] = mapped_column(String, nullable=False)
    filename: Mapped[str] = mapped_column(String, nullable=False)
    uploaded_by: Mapped[UUID] = mapped_column(SA_UUID(as_uuid=True), nullable=False)
    usage_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
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
            f"ServerStickers(sticker_id={self.sticker_id!r}, "
            f"sticker_url={self.sticker_url!r}, "
            f"uploaded_by={self.uploaded_by!r}, "
            f"usage_count={self.usage_count!r})"
        )


class ServerGIFs(Base):
    """Server GIFs catalog table"""

    __tablename__ = "server_gifs"

    gif_id: Mapped[str] = mapped_column(String, primary_key=True, nullable=False)
    gif_url: Mapped[str] = mapped_column(String, nullable=False)
    filename: Mapped[str] = mapped_column(String, nullable=False)
    uploaded_by: Mapped[UUID] = mapped_column(SA_UUID(as_uuid=True), nullable=False)
    usage_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
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
            f"ServerGIFs(gif_id={self.gif_id!r}, "
            f"gif_url={self.gif_url!r}, "
            f"uploaded_by={self.uploaded_by!r}, "
            f"usage_count={self.usage_count!r})"
        )
