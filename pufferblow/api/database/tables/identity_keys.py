"""The public halves of the keys people sign calls with (see ``api/identity/keys.py``)."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from pufferblow.api.database.tables.declarative_base import Base


class IdentityKeys(Base):
    """One signing key a person's device holds. The private half never leaves the device."""

    __tablename__ = "identity_keys"

    #: A fingerprint of the key itself (see ``key_id_of``), so it cannot be made up independently of it.
    key_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), nullable=False)
    #: ``{"kty": "EC", "crv": "P-256", "x": ..., "y": ...}`` as JSON text.
    public_key: Mapped[str] = mapped_column(String(512), nullable=False)
    #: What the owner calls the device ("Laptop"), shown when someone's key changes.
    label: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )

    __table_args__ = (Index("ix_identity_keys_user_id", "user_id"),)

    def to_dict(self) -> dict:
        return {
            "key_id": self.key_id,
            "user_id": self.user_id,
            "public_key": self.public_key,
            "label": self.label,
            "created_at": (self.created_at if self.created_at.tzinfo else self.created_at.replace(tzinfo=timezone.utc)).isoformat(),
        }
