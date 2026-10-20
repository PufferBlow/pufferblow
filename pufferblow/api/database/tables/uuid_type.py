"""A UUID column type that behaves the same on Postgres and SQLite.

On Postgres it is exactly ``postgresql.UUID(as_uuid=True)``, which is what production uses. SQLite has
no native UUID, and SQLAlchemy's generic UUID type refuses a plain string there (``'str' object has no
attribute 'hex'``), although the code passes ids around as strings. On SQLite the column is therefore a
36 character string that accepts a ``uuid.UUID`` or its string form and hands back a ``uuid.UUID``.
That lets the test suite exercise the real routes against an in-memory/temporary SQLite database.
"""

from __future__ import annotations

import uuid

from sqlalchemy import String
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.types import TypeDecorator


class SA_UUID(TypeDecorator):  # noqa: N801 - drop-in for the name the tables already import
    impl = PG_UUID
    cache_ok = True

    def __init__(self, as_uuid: bool = True) -> None:
        super().__init__()
        self._as_uuid = as_uuid

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PG_UUID(as_uuid=self._as_uuid))
        return dialect.type_descriptor(String(36))

    def process_bind_param(self, value, dialect):
        if value is None or dialect.name == "postgresql":
            return value
        return str(uuid.UUID(str(value)))

    def process_result_value(self, value, dialect):
        if value is None or dialect.name == "postgresql":
            return value
        return uuid.UUID(value) if self._as_uuid else value
