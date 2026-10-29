"""Remove the Admin role: owner and moderators only.

Revision ID: 0012
Revises: 0011
Create Date: 2026-10-29

People who held ``admin`` become moderators; the role itself is deleted.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

from pufferblow.api.database import retire_admin

revision: str = "0012"
down_revision: Union[str, None] = "0011"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    retire_admin.apply(op.get_bind())


def downgrade() -> None:
    # The role is not brought back; moderators stay moderators.
    pass
