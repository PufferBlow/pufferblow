"""Rules the database enforces itself, and an append-only ledger of who-may-do-what changes.

Revision ID: 0014
Revises: 0013
Create Date: 2026-11-01

Triggers and constraints (see ``api/database/db_rules.py``): an erased account stays erased, the last owner cannot be
removed, the built-in roles cannot be deleted, a decision on a request to join is final, an invitation cannot be used
past its limit; and ``security_ledger`` (it comes from ``create_all``), which triggers append to and nothing can edit.
PostgreSQL only.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

from pufferblow.api.database import db_rules

revision: str = "0014"
down_revision: Union[str, None] = "0013"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    db_rules.apply(op.get_bind())


def downgrade() -> None:
    # The rules only refuse changes the application never makes; leaving them is harmless.
    pass
