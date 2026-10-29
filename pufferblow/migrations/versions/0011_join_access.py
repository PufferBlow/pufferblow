"""Who may join: members' status, and the privileges that manage invitation codes and join requests.

Revision ID: 0011
Revises: 0010
Create Date: 2026-10-29

Adds ``users.membership_status`` (``active``, ``pending`` or ``denied``) and the ``manage_invites`` and
``manage_join_requests`` privileges, given to the owner, admin and moderator roles. The new tables
(``server_access``, ``server_invites``, ``server_join_requests``, ``federation_assertion_nonces``) come from
``create_all``.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

from pufferblow.api.database import join_access

revision: str = "0011"
down_revision: Union[str, None] = "0010"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    join_access.apply(op.get_bind())


def downgrade() -> None:
    # Dropping a column on every database is not worth the risk; the column is harmless.
    pass
