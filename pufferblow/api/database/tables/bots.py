"""Bot identities. Foundation only: no public API creates or authenticates them yet."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from pufferblow.api.database.tables.declarative_base import Base


class Bots(Base):
    """A bot account, owned by a human user.

    The bot token is never stored. Only ``token_hash`` (a keyed SHA-256 digest)
    and a short non-secret ``token_prefix`` used to find the row are kept; the
    secret itself is shown once, when the bot is created.
    """

    __tablename__ = "bots"

    bot_id: Mapped[str] = mapped_column(String, primary_key=True, nullable=False)
    owner_user_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    #: Privilege names the bot is allowed to use, e.g. ["send_messages"]. Empty means nothing.
    scopes: Mapped[list] = mapped_column(JSON(), nullable=False, default=list)

    token_prefix: Mapped[str] = mapped_column(String, nullable=False, unique=True, index=True)
    token_hash: Mapped[str] = mapped_column(String, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc)
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
