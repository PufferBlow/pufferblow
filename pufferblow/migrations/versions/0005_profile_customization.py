"""Profile customisation: pronouns, a custom status line and a JSON settings object on users.

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-20

All three columns are nullable, so existing rows need no backfill: a null ``profile_settings`` means
"all defaults" (``pufferblow.api.utils.profile_settings.effective_profile_settings`` fills them in).

Defensive against ``create_all`` already having the columns on a fresh install, same pattern as
0002-0004.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_COLUMNS = (
    ("pronouns", lambda: sa.Column("pronouns", sa.String(40), nullable=True)),
    ("custom_status", lambda: sa.Column("custom_status", sa.String(60), nullable=True)),
    ("profile_settings", lambda: sa.Column("profile_settings", sa.JSON(), nullable=True)),
)


def upgrade() -> None:
    existing = {col["name"] for col in sa.inspect(op.get_bind()).get_columns("users")}
    for name, build in _COLUMNS:
        if name not in existing:
            op.add_column("users", build())


def downgrade() -> None:
    existing = {col["name"] for col in sa.inspect(op.get_bind()).get_columns("users")}
    for name, _ in reversed(_COLUMNS):
        if name in existing:
            op.drop_column("users", name)
