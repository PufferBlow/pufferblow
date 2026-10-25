"""Default channel categories: "Text Channels" and "Voice Channels".

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-26

Adds ``channel_categories.default_for`` (``text`` or ``voice``: where new channels of that type land, kept
through a rename) and, on an instance with no categories yet, creates the two defaults and puts the channels that
had no category into them. An instance that already has categories is left as it is.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

from pufferblow.api.database.default_categories import seed_default_categories

# revision identifiers, used by Alembic.
revision: str = "0010"
down_revision: Union[str, None] = "0009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _columns() -> set[str]:
    inspector = sa.inspect(op.get_bind())
    if "channel_categories" not in inspector.get_table_names():
        return set()
    return {col["name"] for col in inspector.get_columns("channel_categories")}


def upgrade() -> None:
    columns = _columns()
    if columns and "default_for" not in columns:
        op.add_column("channel_categories", sa.Column("default_for", sa.String(length=8), nullable=True))
    seed_default_categories(op.get_bind())


def downgrade() -> None:
    if "default_for" in _columns():
        op.drop_column("channel_categories", "default_for")
