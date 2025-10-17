from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID
from sqlalchemy import String, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID as SA_UUID
from sqlalchemy.orm import Mapped, mapped_column
from pufferblow.api.database.tables.declarative_base import Base
from pufferblow.api.utils.current_date import date_in_gmt

class Keys(Base):
    __tablename__ = "keys"

    key_value: Mapped[str] = mapped_column(String, primary_key=True, nullable=False)
    iv: Mapped[str] = mapped_column(String, nullable=False)
    associated_to: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    user_id: Mapped[Optional[UUID]] = mapped_column(SA_UUID(as_uuid=True), ForeignKey("users.user_id", ondelete="CASCADE"), nullable=True)
    message_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("messages.message_id", ondelete="CASCADE"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    def __repr__(self):
        return (
            f"Keys(key_value={self.key_value!r}, iv={self.iv!r}, "
            f"associated_to={self.associated_to!r}, user_id={self.user_id!r}, "
            f"message_id={self.message_id!r}, created_at={self.created_at!r}, "
            f"created_at={self.created_at!r}, updated_at={self.updated_at!r})"
        )

    def to_dict(self) -> dict:
        """ Returns the data in dict format """
        return {
            "key_value"     :   self.key_value,
            "iv"            :   self.iv,            
            "associated_to" :   self.associated_to,
            "user_id"       :   self.user_id,
            "message_id"    :   self.message_id,
            "created_at"    :   self.created_at
        }
