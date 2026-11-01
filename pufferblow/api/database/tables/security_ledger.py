"""An append-only record, kept by the database itself, of the changes that decide who may do what on this server.

The application already writes an audit entry for what people do through it. This is a second record that does not depend
on the application: database triggers write a row whenever someone's roles or membership change, a role is created,
edited or removed, the way people may join changes, or an address is blocked or unblocked, whoever made the change and by
whatever route (including straight SQL). Nothing can edit or delete a row (another trigger refuses). See
``api/database/db_rules.py``.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, BigInteger, DateTime, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from pufferblow.api.database.tables.declarative_base import Base


class SecurityLedger(Base):
    __tablename__ = "security_ledger"

    ledger_id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=True)
    # The database fills it in: the rows are written by triggers, not by the application.
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), server_default=func.now(), index=True)
    #: ``user.roles``, ``user.membership``, ``user.row_deleted``, ``role.created``, ``role.changed``, ``role.deleted``,
    #: ``server.join_mode``, ``ip.blocked``, ``ip.unblocked``.
    kind: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    #: What it is about: a user id, a role id, an address, or ``join_mode``.
    subject: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    old_value: Mapped[dict | list | str | None] = mapped_column(JSON, nullable=True)
    new_value: Mapped[dict | list | str | None] = mapped_column(JSON, nullable=True)
    #: Who the application said was acting, when it said (``SET LOCAL pufferblow.actor = '<user id>'``); else empty.
    actor: Mapped[str | None] = mapped_column(String(64), nullable=True)
    #: The database login that made the change.
    db_user: Mapped[str | None] = mapped_column(String(64), nullable=True)
