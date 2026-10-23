"""Server look: the icon style, colours and banner pattern the owner chose.

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-23

One nullable JSON column on ``server``. Null means "nothing chosen": clients draw the look derived from
the server's id, as they did before. Defensive against ``create_all`` already having the column on a
fresh install, the same pattern as 0002-0006.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0007"
down_revision: Union[str, None] = "0006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _columns() -> set[str]:
    return {col["name"] for col in sa.inspect(op.get_bind()).get_columns("server")}


def upgrade() -> None:
    if "profile_settings" not in _columns():
        op.add_column("server", sa.Column("profile_settings", sa.JSON(), nullable=True))


def downgrade() -> None:
    if "profile_settings" in _columns():
        op.drop_column("server", "profile_settings")
