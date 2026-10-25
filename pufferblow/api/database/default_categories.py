"""The two categories every instance starts with, and the step that gives existing channels to them."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import sqlalchemy as sa

TEXT_NAME = "Text Channels"
VOICE_NAME = "Voice Channels"


def seed_default_categories(connection) -> bool:
    """Create "Text Channels" and "Voice Channels" and put the channels that have no category into them.

    Only when the instance has no categories at all: one that already organised its channels keeps what it made.
    Returns whether anything was created. Safe to run twice.
    """
    tables = sa.inspect(connection).get_table_names()
    if "channel_categories" not in tables or "channels" not in tables:
        return False
    if connection.execute(sa.text("SELECT COUNT(*) FROM channel_categories")).scalar():
        return False

    now = datetime.now(timezone.utc)
    made: dict[str, str] = {}
    for position, (kind, name) in enumerate((("text", TEXT_NAME), ("voice", VOICE_NAME))):
        category_id = str(uuid.uuid4())
        made[kind] = category_id
        connection.execute(
            sa.text("INSERT INTO channel_categories (category_id, name, position, default_for, created_at) VALUES (:id, :name, :position, :kind, :now)").bindparams(
                sa.bindparam("now", type_=sa.DateTime(timezone=True))
            ),
            {"id": category_id, "name": name, "position": position, "kind": kind, "now": now},
        )
    connection.execute(
        sa.text("UPDATE channels SET category_id = :id WHERE category_id IS NULL AND channel_type = 'voice'"), {"id": made["voice"]}
    )
    connection.execute(
        sa.text("UPDATE channels SET category_id = :id WHERE category_id IS NULL AND channel_type <> 'voice'"), {"id": made["text"]}
    )
    return True
