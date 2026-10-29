"""What an existing database needs for join modes, invitation codes and join requests.

New tables come from ``create_all``. What an existing install lacks is a column on ``users`` and two privileges
(default seeding is skipped once privileges exist), so this adds them, safely to run again. It is used at boot and by
Alembic revision 0011.
"""

from __future__ import annotations

from datetime import datetime, timezone

import sqlalchemy as sa

NEW_PRIVILEGES = (
    ("manage_invites", "Manage Invitation Codes", "moderation"),
    ("manage_join_requests", "Manage Join Requests", "moderation"),
)

#: The built-in roles that get them. Owner and admin run the server; moderators decide who comes in.
ROLES_WITH_ACCESS_PRIVILEGES = ("owner", "admin", "moderator")


def apply(bind) -> None:
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "users" in tables and "membership_status" not in {c["name"] for c in inspector.get_columns("users")}:
        bind.execute(sa.text("ALTER TABLE users ADD COLUMN membership_status VARCHAR(12) NOT NULL DEFAULT 'active'"))
        # People who exist here only because they federated (DMs, friend requests) have not joined anything.
        bind.execute(sa.text("UPDATE users SET membership_status = 'remote' WHERE username LIKE :pattern ESCAPE '!'"), {"pattern": "fedi!_%"})

    if "server_join_requests" in tables and "consumed_at" not in {c["name"] for c in inspector.get_columns("server_join_requests")}:
        bind.execute(sa.text("ALTER TABLE server_join_requests ADD COLUMN consumed_at TIMESTAMP"))

    if "privileges" in tables:
        existing = {row[0] for row in bind.execute(sa.text("SELECT privilege_id FROM privileges"))}
        # A database with no privileges yet is a new one: its first start seeds the whole catalog, these included.
        # Adding two here would make that seeding think it had already been done.
        for privilege_id, name, category in NEW_PRIVILEGES if existing else ():
            if privilege_id not in existing:
                bind.execute(
                    sa.text("INSERT INTO privileges (privilege_id, privilege_name, category, created_at) VALUES (:id, :name, :category, :now)"),
                    {"id": privilege_id, "name": name, "category": category, "now": datetime.now(timezone.utc)},
                )

    if "roles" in tables:
        import json

        for role_id in ROLES_WITH_ACCESS_PRIVILEGES:
            row = bind.execute(sa.text("SELECT privileges_ids FROM roles WHERE role_id = :id"), {"id": role_id}).first()
            if row is None:
                continue
            current = row[0]
            if isinstance(current, str):
                current = json.loads(current or "[]")
            current = list(current or [])
            changed = False
            for privilege_id, _name, _category in NEW_PRIVILEGES:
                if privilege_id not in current:
                    current.append(privilege_id)
                    changed = True
            if changed:
                dialect = bind.dialect.name
                if dialect == "postgresql":
                    bind.execute(sa.text("UPDATE roles SET privileges_ids = :ids WHERE role_id = :id"), {"ids": current, "id": role_id})
                else:
                    bind.execute(sa.text("UPDATE roles SET privileges_ids = :ids WHERE role_id = :id"), {"ids": json.dumps(current), "id": role_id})
