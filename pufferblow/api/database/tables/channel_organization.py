"""How channels are organised: the categories they sit in, and the messages pinned in them."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from pufferblow.api.database.tables.declarative_base import Base


class ChannelCategories(Base):
    """A named group of channels ("Information", "Community"). Instance-wide; channels point at one."""

    __tablename__ = "channel_categories"

    category_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    #: Order among categories, smallest first.
    position: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    #: ``"text"`` or ``"voice"`` on the category that new channels of that type land in, so it survives being renamed.
    default_for: Mapped[str | None] = mapped_column(String(8), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self) -> dict:
        return {"category_id": self.category_id, "name": self.name, "position": self.position, "default_for": self.default_for}


class PinnedMessages(Base):
    """A message pinned in its channel."""

    __tablename__ = "pinned_messages"

    channel_id: Mapped[str] = mapped_column(String, primary_key=True)
    message_id: Mapped[str] = mapped_column(String, primary_key=True)
    pinned_by: Mapped[str] = mapped_column(String, nullable=False)
    pinned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
