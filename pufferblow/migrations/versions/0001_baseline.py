"""Baseline — marks "schema already at the pre-Alembic current state".

Revision ID: 0001
Revises:
Create Date: 2026-10-12

By the time this runs, `DatabaseHandler.__init__` has already brought the
schema up to date via `create_all` plus the hand-rolled `_apply_*_migration`
methods (see `pufferblow/api/database/database_handler.py`) — that's true
for every already-deployed instance as well as a brand-new install. So this
revision intentionally does nothing; it only gives the Alembic chain a
starting point. Real schema changes from here on are added as new revisions
with `down_revision = "0001"` (or whatever the current head is).
"""
from __future__ import annotations

from typing import Sequence, Union

# revision identifiers, used by Alembic.
revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
