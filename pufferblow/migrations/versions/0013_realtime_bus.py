"""The database side of the cross-worker realtime bus.

Revision ID: 0013
Revises: 0012
Create Date: 2026-11-01

Adds the two small tables the workers share (``realtime_meta``, ``realtime_spool``; they also come from ``create_all``)
and the triggers that notify every worker when roles, membership, settings or blocked addresses change. PostgreSQL only.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

from pufferblow.api.database import bus_setup

revision: str = "0013"
down_revision: Union[str, None] = "0012"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bus_setup.apply(op.get_bind())


def downgrade() -> None:
    # The triggers only send notifications; leaving them is harmless.
    pass
