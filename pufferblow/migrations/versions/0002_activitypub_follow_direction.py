"""Add direction to activitypub_follows.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-12

``activitypub_follows`` had no column distinguishing "the local actor
follows the remote actor" (outgoing, written by ``send_follow``) from "the
remote actor follows the local actor" (incoming, written by
``_handle_follow``) — both produce a row with the same
``(local_actor_uri, remote_actor_uri)`` shape. That's exactly the
distinction a followers-vs-following collection needs. Existing rows
default to ``'incoming'`` since the auto-accepting inbound path is the
dominant real-world write path so far; a mutual follow between the same
pair still collides into one row either way (the unique constraint on
``(local_actor_uri, remote_actor_uri)`` isn't touched here — tracking both
directions for the same pair independently is a larger follow-up, not a
blocker for exposing the collections that already work correctly).
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Defensive: on a brand-new install, DatabaseHandler.__init__'s create_all()
    # already created this table from the current ORM model (which, by the
    # time this migration ships, declares `direction` directly) — so the
    # column exists before this migration ever runs. Only an instance
    # upgrading from before this column existed actually needs the ALTER.
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = {col["name"] for col in inspector.get_columns("activitypub_follows")}
    if "direction" not in existing:
        op.add_column(
            "activitypub_follows",
            sa.Column("direction", sa.String(length=16), nullable=False, server_default="incoming"),
        )


def downgrade() -> None:
    op.drop_column("activitypub_follows", "direction")
