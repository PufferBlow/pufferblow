from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import ARRAY, JSON, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from pufferblow.api.database.tables.declarative_base import Base
class Roles(Base):
    """Roles table"""

    __tablename__ = "roles"

    role_id: Mapped[str] = mapped_column(String, primary_key=True, nullable=False)
    role_name: Mapped[str] = mapped_column(String, nullable=False)
    privileges_ids: Mapped[list[str]] = mapped_column(
        ARRAY(String).with_variant(JSON(), "sqlite"),
        nullable=False,
        default=list,
    )

    # The mark shown after a person's name: {"tier", "tone", "glyph", "image_url"?}. Null: no badge of its own
    # (the built-in Owner, Admin and Moderator roles are shown with theirs, see api/utils/role_badges.py).
    badge: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    def __repr__(self) -> str:
        """Repr special method."""
        return (
            f"Roles(role_id={self.role_id!r}, role_name={self.role_name!r}, "
            f"privileges_ids={self.privileges_ids!r}, "
            f"created_at={self.created_at!r}, updated_at={self.updated_at!r})"
        )
