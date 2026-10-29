"""There is no Admin role: a server has an owner and moderators.

An existing install may still have the built-in ``admin`` role and people holding it. They become moderators (the
nearest role that is left) and the role is removed. Safe to run again. Used at boot and by Alembic revision 0012.
"""

from __future__ import annotations

import json

import sqlalchemy as sa


def apply(bind) -> None:
    tables = set(sa.inspect(bind).get_table_names())
    if "roles" not in tables:
        return

    if "users" in tables:
        rows = bind.execute(sa.text("SELECT user_id, roles_ids FROM users")).all()
        for user_id, roles in rows:
            if isinstance(roles, str):
                roles = json.loads(roles or "[]")
            roles = list(roles or [])
            if "admin" not in roles:
                continue
            kept = [role for role in roles if role != "admin"]
            if "moderator" not in kept and "owner" not in kept:
                kept.append("moderator")
            bind.execute(sa.text("UPDATE users SET roles_ids = :roles WHERE user_id = :id"), {"roles": json.dumps(kept), "id": user_id})

    bind.execute(sa.text("DELETE FROM roles WHERE role_id = 'admin'"))
