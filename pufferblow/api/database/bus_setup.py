"""The database triggers that tell every worker when something it may have cached has changed.

PostgreSQL only (other databases get nothing and keep relying on the code that makes a change to invalidate it). Each
trigger sends a ``pufferblow_cache`` notification, ``{"t": kind, "id": ...}``, when the change commits; every worker is
listening (see ``api/events/pg_bus.py``) and drops its cached copies. Safe to run again: the functions are replaced and
the triggers recreated. Used at boot and by Alembic revision 0013.

What counts as a change worth telling about is deliberately narrow, because a notification costs every worker a little:

* ``users``: roles, membership (removed, waiting, erased) or name. Not presence or last seen, which change all the time
  and are handled by the code that makes them.
* ``roles``: any change (they are rare).
* ``server_settings``: any change.
* ``blocked_ips``: an address blocked, unblocked or changed.
"""

from __future__ import annotations

import sqlalchemy as sa

FUNCTIONS = {
    "pufferblow_notify_user": """
        CREATE OR REPLACE FUNCTION pufferblow_notify_user() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            PERFORM pg_notify('pufferblow_cache', json_build_object('t', 'user', 'id', OLD.user_id::text)::text);
            RETURN OLD;
          END IF;
          PERFORM pg_notify('pufferblow_cache', json_build_object('t', 'user', 'id', NEW.user_id::text)::text);
          RETURN NEW;
        END $$;
    """,
    "pufferblow_notify_role": """
        CREATE OR REPLACE FUNCTION pufferblow_notify_role() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            PERFORM pg_notify('pufferblow_cache', json_build_object('t', 'role', 'id', OLD.role_id::text)::text);
            RETURN OLD;
          END IF;
          PERFORM pg_notify('pufferblow_cache', json_build_object('t', 'role', 'id', NEW.role_id::text)::text);
          RETURN NEW;
        END $$;
    """,
    "pufferblow_notify_settings": """
        CREATE OR REPLACE FUNCTION pufferblow_notify_settings() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          PERFORM pg_notify('pufferblow_cache', json_build_object('t', 'settings', 'id', '')::text);
          RETURN NULL;
        END $$;
    """,
    "pufferblow_notify_ip": """
        CREATE OR REPLACE FUNCTION pufferblow_notify_ip() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            PERFORM pg_notify('pufferblow_cache', json_build_object('t', 'ip', 'id', OLD.ip::text)::text);
            RETURN OLD;
          END IF;
          PERFORM pg_notify('pufferblow_cache', json_build_object('t', 'ip', 'id', NEW.ip::text)::text);
          RETURN NEW;
        END $$;
    """,
}

#: (table, trigger name, definition after the name). `roles_ids` is JSON (no equality operator), so it is compared as text.
TRIGGERS = (
    (
        "users",
        "pufferblow_users_changed",
        """AFTER UPDATE ON users FOR EACH ROW
           WHEN (OLD.roles_ids::text IS DISTINCT FROM NEW.roles_ids::text
                 OR OLD.membership_status IS DISTINCT FROM NEW.membership_status
                 OR OLD.username IS DISTINCT FROM NEW.username)
           EXECUTE FUNCTION pufferblow_notify_user()""",
    ),
    ("users", "pufferblow_users_removed", "AFTER DELETE ON users FOR EACH ROW EXECUTE FUNCTION pufferblow_notify_user()"),
    ("roles", "pufferblow_roles_changed", "AFTER INSERT OR UPDATE OR DELETE ON roles FOR EACH ROW EXECUTE FUNCTION pufferblow_notify_role()"),
    ("server_settings", "pufferblow_settings_changed", "AFTER INSERT OR UPDATE ON server_settings FOR EACH STATEMENT EXECUTE FUNCTION pufferblow_notify_settings()"),
    ("blocked_ips", "pufferblow_ips_changed", "AFTER INSERT OR UPDATE OR DELETE ON blocked_ips FOR EACH ROW EXECUTE FUNCTION pufferblow_notify_ip()"),
)


def apply(bind) -> None:
    """Install or refresh the functions and triggers (PostgreSQL only; a table that is not there yet is skipped)."""
    if bind.dialect.name != "postgresql":
        return
    tables = set(sa.inspect(bind).get_table_names())
    for sql in FUNCTIONS.values():
        bind.execute(sa.text(sql))
    for table, name, definition in TRIGGERS:
        if table not in tables:
            continue
        bind.execute(sa.text(f"DROP TRIGGER IF EXISTS {name} ON {table}"))
        bind.execute(sa.text(f"CREATE TRIGGER {name} {definition}"))
