from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from pufferblow.api.database.tables.declarative_base import Base
class BlockedIPS(Base):
    """BlockedIPS table"""

    __tablename__ = "blocked_ips"

    ip_id: Mapped[str] = mapped_column(String, primary_key=True, nullable=False)
    ip: Mapped[str] = mapped_column(String, nullable=False, unique=True, index=True)
    block_reason: Mapped[str] = mapped_column(String, nullable=False)
    blocked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
    # Number of requests that were rejected because this IP was on the
    # blocklist. Incremented from the rate-limit middleware every time
    # a blocked IP hits the API, so operators can see whether a block
    # is still under attack or has quietly tapered off. Defaults to 0
    # so existing rows backfill cleanly when the column is added.
    block_attempts_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )
    last_attempt_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    def __repr__(self):
        """Repr special method."""
        return (
            f"BlockedIPS(ip_id={self.ip_id!r}, ip={self.ip!r}, "
            f"block_reason={self.block_reason!r}, blocked_at={self.blocked_at!r}, "
            f"block_attempts_count={self.block_attempts_count!r})"
        )

    def to_dict(self) -> dict:
        """To dict."""
        return {
            "ip_id": self.ip_id,
            "ip": self.ip,
            "block_reason": self.block_reason,
            "blocked_at": self.blocked_at,
            "block_attempts_count": self.block_attempts_count,
            "last_attempt_at": self.last_attempt_at,
        }
