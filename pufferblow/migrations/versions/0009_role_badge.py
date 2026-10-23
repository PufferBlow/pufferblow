"""Role badges: the mark a role carries after a person's name.

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-23

One nullable JSON column on ``roles``: ``{"tier", "tone", "glyph", "image_url"?}``. Null means no badge,
and the built-in Owner, Admin and Moderator roles are shown with theirs without storing anything.
Defensive against ``create_all`` already having the column on a fresh install.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0009"
down_revision: Union[str, None] = "0008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _columns() -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if "roles" not in inspector.get_table_names():
        return set()
    return {col["name"] for col in inspector.get_columns("roles")}


def upgrade() -> None:
    columns = _columns()
    if columns and "badge" not in columns:
        op.add_column("roles", sa.Column("badge", sa.JSON(), nullable=True))


def downgrade() -> None:
    if "badge" in _columns():
        op.drop_column("roles", "badge")
