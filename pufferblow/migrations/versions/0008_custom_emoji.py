"""Custom emoji: the sticker catalog holds them too, told apart by a kind.

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-23

One column on ``server_stickers``: ``kind`` is ``sticker`` (the default, so every existing row stays a
sticker) or ``emoji``. An emoji is a small picture with a ``:shortcode:`` that can be typed into a message
or used as a reaction (``sticker:<id>``, as stickers already are). Defensive against ``create_all``
already having the column on a fresh install, the same pattern as 0002-0007.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0008"
down_revision: Union[str, None] = "0007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _columns() -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if "server_stickers" not in inspector.get_table_names():
        return set()
    return {col["name"] for col in inspector.get_columns("server_stickers")}


def upgrade() -> None:
    columns = _columns()
    if columns and "kind" not in columns:
        op.add_column("server_stickers", sa.Column("kind", sa.String(length=16), nullable=False, server_default="sticker"))


def downgrade() -> None:
    if "kind" in _columns():
        op.drop_column("server_stickers", "kind")
