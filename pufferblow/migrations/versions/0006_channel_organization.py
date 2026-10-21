"""Channel organisation: a category, a position and a topic on channels.

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-21

``channel_categories`` and ``pinned_messages`` are new tables, which ``create_all`` makes; only the three
columns on ``channels`` need adding. All are nullable or defaulted, so existing channels keep working and
simply have no category, position 0 and no topic. Defensive against ``create_all`` already having the
columns on a fresh install, the same pattern as 0002-0005.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0006"
down_revision: Union[str, None] = "0005"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_COLUMNS = (
    ("category_id", lambda: sa.Column("category_id", sa.String(36), nullable=True)),
    ("position", lambda: sa.Column("position", sa.Integer(), nullable=False, server_default="0")),
    ("topic", lambda: sa.Column("topic", sa.String(256), nullable=True)),
)


def upgrade() -> None:
    existing = {col["name"] for col in sa.inspect(op.get_bind()).get_columns("channels")}
    for name, build in _COLUMNS:
        if name not in existing:
            op.add_column("channels", build())


def downgrade() -> None:
    existing = {col["name"] for col in sa.inspect(op.get_bind()).get_columns("channels")}
    for name, _ in reversed(_COLUMNS):
        if name in existing:
            op.drop_column("channels", name)
