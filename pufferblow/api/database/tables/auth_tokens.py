from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from uuid import UUID
from sqlalchemy import String, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID as SA_UUID
from sqlalchemy.orm import Mapped, mapped_column
from pufferblow.api.database.tables.declarative_base import Base


class AuthTokens(Base):
    """AuthTokens table"""
    __tablename__ = "auth_tokens"

    auth_token: Mapped[str] = mapped_column(String, primary_key=True, nullable=False)
    auth_token_expire_time: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    user_id: Mapped[Optional[UUID]] = mapped_column(SA_UUID(as_uuid=True), ForeignKey("users.user_id", ondelete="CASCADE"), nullable=True)
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    def __repr__(self):
        return (
            f"AuthTokens("
            f"auth_token={self.auth_token!r}, "
            f"auth_token_expire_time={self.auth_token_expire_time!r}, "
            f"user_id={self.user_id!r}, "
            f"updated_at={self.updated_at!r})"
        )
