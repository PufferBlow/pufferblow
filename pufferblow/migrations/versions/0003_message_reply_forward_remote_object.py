"""Add reply/forward threading + remote object tracking to messages.

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-12

Three nullable, independent additions to `messages`:

  * `reply_to_message_id` — self-FK, set when a message is a reply to
    another message (channel or DM).
  * `forwarded_from_message_id` — self-FK, set when a message was created
    by forwarding another message (channel-to-DM or DM-to-DM).
  * `remote_object_uri` — the ORIGINAL ActivityPub object id for a message
    that arrived via an inbound Create (i.e. the remote peer authored it).
    Null for locally-authored messages. This is what lets a later inbound
    Update/Delete/Like actually find the local row it targets, instead of
    only being acknowledged — `_handle_create` didn't persist this before,
    which meant `_handle_update`/`_handle_delete` had no way to resolve a
    remote object id back to a local message_id.

Defensive against `create_all` already having these columns on a fresh
install, same as 0002.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_COLUMNS = (
    ("reply_to_message_id", sa.String(), {"nullable": True}),
    ("forwarded_from_message_id", sa.String(), {"nullable": True}),
    ("remote_object_uri", sa.String(), {"nullable": True}),
)


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = {col["name"] for col in inspector.get_columns("messages")}

    for name, col_type, kwargs in _COLUMNS:
        if name in existing:
            continue
        op.add_column("messages", sa.Column(name, col_type, **kwargs))

    existing_indexes = {ix["name"] for ix in inspector.get_indexes("messages")}
    if "ix_messages_remote_object_uri" not in existing_indexes and "remote_object_uri" not in existing:
        op.create_index("ix_messages_remote_object_uri", "messages", ["remote_object_uri"])


def downgrade() -> None:
    op.drop_index("ix_messages_remote_object_uri", table_name="messages")
    op.drop_column("messages", "remote_object_uri")
    op.drop_column("messages", "forwarded_from_message_id")
    op.drop_column("messages", "reply_to_message_id")
