from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.dialects.postgresql import UUID as SA_UUID
from sqlalchemy.orm import Mapped, mapped_column

from pufferblow.api.database.tables.declarative_base import Base


class ServerStickers(Base):
    """Server stickers catalog table.

    One row per uploaded sticker. Rows are mutable on the metadata
    columns (``display_name``, ``alias``, ``is_active``) so admins can
    rename / retire stickers without breaking already-sent messages
    (the message_attachments still reference the stable ``sticker_id``
    and the storage-backed ``sticker_url``).

    The actual sticker bytes live in storage (deduped via
    ``file_objects.file_hash`` ref-counting) so deleting a sticker
    row only deletes the file when the last reference is dropped —
    older messages keep rendering.
    """

    __tablename__ = "server_stickers"

    sticker_id: Mapped[str] = mapped_column(String, primary_key=True, nullable=False)
    sticker_url: Mapped[str] = mapped_column(String, nullable=False, index=True)
    filename: Mapped[str] = mapped_column(String, nullable=False)
    # User-facing label shown in the picker grid. Stays separate from
    # ``filename`` so admins can rename "smiling_cat_v2_FINAL.png" to
    # "Happy Cat" without touching the storage layer. Indexed so the
    # picker can prefix-search by name.
    display_name: Mapped[str] = mapped_column(String(64), nullable=False, default="", index=True)
    # Optional shortcode for type-to-send (e.g. ``:party_parrot:``).
    # Nullable: not every sticker needs one. When set, must be unique
    # per instance so the chat input can map ``:foo:`` deterministically.
    alias: Mapped[str | None] = mapped_column(String(48), nullable=True, unique=True, index=True)
    uploaded_by: Mapped[UUID] = mapped_column(SA_UUID(as_uuid=True), nullable=False, index=True)
    usage_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    def to_dict(self) -> dict:
        """Serialise to the client-facing wire shape."""
        return {
            "sticker_id": self.sticker_id,
            "sticker_url": self.sticker_url,
            "filename": self.filename,
            "display_name": self.display_name or self.filename,
            "alias": self.alias,
            "uploaded_by": str(self.uploaded_by) if self.uploaded_by else None,
            "usage_count": self.usage_count,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        """Repr special method."""
        return (
            f"ServerStickers(sticker_id={self.sticker_id!r}, "
            f"display_name={self.display_name!r}, "
            f"alias={self.alias!r}, "
            f"usage_count={self.usage_count!r})"
        )


class ServerGIFs(Base):
    """Server GIFs catalog table"""

    __tablename__ = "server_gifs"

    gif_id: Mapped[str] = mapped_column(String, primary_key=True, nullable=False)
    gif_url: Mapped[str] = mapped_column(String, nullable=False, index=True)
    filename: Mapped[str] = mapped_column(String, nullable=False)
    uploaded_by: Mapped[UUID] = mapped_column(SA_UUID(as_uuid=True), nullable=False, index=True)
    usage_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    def __repr__(self) -> str:
        """Repr special method."""
        return (
            f"ServerGIFs(gif_id={self.gif_id!r}, "
            f"gif_url={self.gif_url!r}, "
            f"uploaded_by={self.uploaded_by!r}, "
            f"usage_count={self.usage_count!r})"
        )
