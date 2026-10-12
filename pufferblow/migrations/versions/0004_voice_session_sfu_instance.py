"""Add sfu_instance_id to voice_sessions, for the multi-instance SFU registry.

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-12

Nullable column recording which `media_sfu_instances.instance_id` a voice
session was placed on, so a reconnect sticks to the same instance until it's
marked draining/dead instead of being handed a fresh random pick each time.
Null on rows created before the registry existed, or on a deployment with no
registered instances (single hardcoded-signaling-url fallback still works).

Defensive against `create_all` already having the column on a fresh install,
same pattern as 0002/0003. `media_sfu_instances` itself is a brand new table
and does not need a migration — `create_all` is sufficient for new tables.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = {col["name"] for col in inspector.get_columns("voice_sessions")}

    if "sfu_instance_id" not in existing:
        op.add_column(
            "voice_sessions", sa.Column("sfu_instance_id", sa.String(), nullable=True)
        )

    existing_indexes = {ix["name"] for ix in inspector.get_indexes("voice_sessions")}
    if (
        "ix_voice_sessions_sfu_instance_id" not in existing_indexes
        and "sfu_instance_id" not in existing
    ):
        op.create_index(
            "ix_voice_sessions_sfu_instance_id", "voice_sessions", ["sfu_instance_id"]
        )


def downgrade() -> None:
    op.drop_index("ix_voice_sessions_sfu_instance_id", table_name="voice_sessions")
    op.drop_column("voice_sessions", "sfu_instance_id")
