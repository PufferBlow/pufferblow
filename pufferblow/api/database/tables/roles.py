from __future__ import annotations

from datetime import datetime

from sqlalchemy import ARRAY, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from pufferblow.api.database.tables.declarative_base import Base
from pufferblow.api.utils.current_date import date_in_gmt


class Roles(Base):
    """Roles table"""

    __tablename__ = "roles"

    role_id: Mapped[str] = mapped_column(String, primary_key=True, nullable=False)
    role_name: Mapped[str] = mapped_column(String, nullable=False)
    privileges_ids: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=date_in_gmt, nullable=False
    )
    updated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    def __repr__(self) -> str:
        return (
            f"Roles(role_id={self.role_id!r}, role_name={self.role_name!r}, "
            f"privileges_ids={self.privileges_ids!r}, "
            f"created_at={self.created_at!r}, updated_at={self.updated_at!r})"
        )
