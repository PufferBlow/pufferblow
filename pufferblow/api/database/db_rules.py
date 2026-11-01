"""Rules the database itself enforces, and the ledger it keeps.

PostgreSQL only; other databases get nothing and rely on the application, which already follows every one of these
rules. These are the backstop for when it does not: a bug, a second code path, a person at a SQL prompt. Safe to run
again. Used at boot and by Alembic revision 0014.

Rules (each refusal says so with a message that starts ``pufferblow:``, which the API turns into a plain 409):

* an erased account stays erased (``deleted`` is a final state);
* the last active owner cannot lose the owner role, be removed, be erased or have the row deleted;
* the built-in roles (owner, moderator, user) cannot be deleted;
* a decision on a request to join is final, and an approval, once used, stays used;
* an invitation code cannot have been used more than its limit;
* ``membership_status`` is one of the known values.

The ledger (``security_ledger``) is appended to by triggers and cannot be edited or deleted from.
"""

from __future__ import annotations

import sqlalchemy as sa

MEMBERSHIP_VALUES = ("active", "pending", "denied", "remote", "kicked", "deleted")
BUILT_IN_ROLES = ("owner", "moderator", "user")

FUNCTIONS = {
    "pufferblow_users_guard": """
        CREATE OR REPLACE FUNCTION pufferblow_users_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE
          was_owner boolean := COALESCE(jsonb_exists(OLD.roles_ids::jsonb, 'owner'), false);
          stays_owner boolean;
        BEGIN
          IF TG_OP = 'UPDATE' THEN
            IF OLD.membership_status = 'deleted' AND NEW.membership_status <> 'deleted' THEN
              RAISE EXCEPTION 'pufferblow: an erased account cannot be brought back';
            END IF;
            stays_owner := COALESCE(jsonb_exists(NEW.roles_ids::jsonb, 'owner'), false) AND NEW.membership_status = 'active';
          ELSE
            stays_owner := false;
          END IF;

          IF was_owner AND OLD.membership_status = 'active' AND NOT stays_owner THEN
            IF NOT EXISTS (
              SELECT 1 FROM users u
              WHERE u.user_id <> OLD.user_id AND u.membership_status = 'active' AND COALESCE(jsonb_exists(u.roles_ids::jsonb, 'owner'), false)
            ) THEN
              RAISE EXCEPTION 'pufferblow: the last owner cannot be removed. Hand the server over first';
            END IF;
          END IF;

          IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
          RETURN NEW;
        END $$;
    """,
    "pufferblow_roles_guard": f"""
        CREATE OR REPLACE FUNCTION pufferblow_roles_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF OLD.role_id IN ({", ".join(repr(r) for r in BUILT_IN_ROLES)}) THEN
            RAISE EXCEPTION 'pufferblow: the built-in role % cannot be deleted', OLD.role_id;
          END IF;
          RETURN OLD;
        END $$;
    """,
    "pufferblow_join_requests_guard": """
        CREATE OR REPLACE FUNCTION pufferblow_join_requests_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF OLD.status <> 'pending' AND NEW.status IS DISTINCT FROM OLD.status THEN
            RAISE EXCEPTION 'pufferblow: a decision on a request to join is final';
          END IF;
          IF OLD.consumed_at IS NOT NULL AND NEW.consumed_at IS DISTINCT FROM OLD.consumed_at THEN
            RAISE EXCEPTION 'pufferblow: an approval can be used only once';
          END IF;
          RETURN NEW;
        END $$;
    """,
    "pufferblow_ledger_guard": """
        CREATE OR REPLACE FUNCTION pufferblow_ledger_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          RAISE EXCEPTION 'pufferblow: the security ledger is append-only';
        END $$;
    """,
    "pufferblow_ledger": """
        CREATE OR REPLACE FUNCTION pufferblow_ledger() RETURNS trigger LANGUAGE plpgsql AS $$
        DECLARE who text := nullif(current_setting('pufferblow.actor', true), '');
        BEGIN
          IF TG_TABLE_NAME = 'users' THEN
            IF TG_OP = 'DELETE' THEN
              INSERT INTO security_ledger (kind, subject, old_value, actor, db_user)
              VALUES ('user.row_deleted', OLD.user_id::text, json_build_object('username', OLD.username, 'roles', OLD.roles_ids, 'membership', OLD.membership_status), who, current_user);
              RETURN OLD;
            END IF;
            IF OLD.roles_ids::text IS DISTINCT FROM NEW.roles_ids::text THEN
              INSERT INTO security_ledger (kind, subject, old_value, new_value, actor, db_user)
              VALUES ('user.roles', NEW.user_id::text, OLD.roles_ids, NEW.roles_ids, who, current_user);
            END IF;
            IF OLD.membership_status IS DISTINCT FROM NEW.membership_status THEN
              INSERT INTO security_ledger (kind, subject, old_value, new_value, actor, db_user)
              VALUES ('user.membership', NEW.user_id::text, to_json(OLD.membership_status), to_json(NEW.membership_status), who, current_user);
            END IF;
            RETURN NEW;

          ELSIF TG_TABLE_NAME = 'roles' THEN
            IF TG_OP = 'INSERT' THEN
              INSERT INTO security_ledger (kind, subject, new_value, actor, db_user)
              VALUES ('role.created', NEW.role_id::text, to_json(NEW.privileges_ids), who, current_user);
              RETURN NEW;
            ELSIF TG_OP = 'DELETE' THEN
              INSERT INTO security_ledger (kind, subject, old_value, actor, db_user)
              VALUES ('role.deleted', OLD.role_id::text, to_json(OLD.privileges_ids), who, current_user);
              RETURN OLD;
            END IF;
            IF OLD.privileges_ids::text IS DISTINCT FROM NEW.privileges_ids::text THEN
              INSERT INTO security_ledger (kind, subject, old_value, new_value, actor, db_user)
              VALUES ('role.changed', NEW.role_id::text, to_json(OLD.privileges_ids), to_json(NEW.privileges_ids), who, current_user);
            END IF;
            RETURN NEW;

          ELSIF TG_TABLE_NAME = 'server_access' THEN
            IF OLD.join_mode IS DISTINCT FROM NEW.join_mode THEN
              INSERT INTO security_ledger (kind, subject, old_value, new_value, actor, db_user)
              VALUES ('server.join_mode', 'join_mode', to_json(OLD.join_mode), to_json(NEW.join_mode), who, current_user);
            END IF;
            RETURN NEW;

          ELSIF TG_TABLE_NAME = 'blocked_ips' THEN
            IF TG_OP = 'DELETE' THEN
              INSERT INTO security_ledger (kind, subject, actor, db_user) VALUES ('ip.unblocked', OLD.ip::text, who, current_user);
              RETURN OLD;
            END IF;
            IF TG_OP = 'INSERT' THEN
              INSERT INTO security_ledger (kind, subject, actor, db_user) VALUES ('ip.blocked', NEW.ip::text, who, current_user);
            END IF;
            RETURN NEW;
          END IF;
          RETURN NULL;
        END $$;
    """,
}

#: (table, trigger name, definition after the name)
TRIGGERS = (
    (
        "users",
        "pufferblow_users_guard_update",
        """BEFORE UPDATE ON users FOR EACH ROW
           WHEN (OLD.roles_ids::text IS DISTINCT FROM NEW.roles_ids::text OR OLD.membership_status IS DISTINCT FROM NEW.membership_status)
           EXECUTE FUNCTION pufferblow_users_guard()""",
    ),
    ("users", "pufferblow_users_guard_delete", "BEFORE DELETE ON users FOR EACH ROW EXECUTE FUNCTION pufferblow_users_guard()"),
    ("roles", "pufferblow_roles_guard_delete", "BEFORE DELETE ON roles FOR EACH ROW EXECUTE FUNCTION pufferblow_roles_guard()"),
    ("server_join_requests", "pufferblow_join_requests_guard_update", "BEFORE UPDATE ON server_join_requests FOR EACH ROW EXECUTE FUNCTION pufferblow_join_requests_guard()"),
    ("security_ledger", "pufferblow_ledger_append_only", "BEFORE UPDATE OR DELETE ON security_ledger FOR EACH ROW EXECUTE FUNCTION pufferblow_ledger_guard()"),
    (
        "users",
        "pufferblow_ledger_users_update",
        """AFTER UPDATE OF roles_ids, membership_status ON users FOR EACH ROW
           WHEN (OLD.roles_ids::text IS DISTINCT FROM NEW.roles_ids::text OR OLD.membership_status IS DISTINCT FROM NEW.membership_status)
           EXECUTE FUNCTION pufferblow_ledger()""",
    ),
    ("users", "pufferblow_ledger_users_delete", "AFTER DELETE ON users FOR EACH ROW EXECUTE FUNCTION pufferblow_ledger()"),
    ("roles", "pufferblow_ledger_roles", "AFTER INSERT OR UPDATE OR DELETE ON roles FOR EACH ROW EXECUTE FUNCTION pufferblow_ledger()"),
    ("server_access", "pufferblow_ledger_join_mode", "AFTER UPDATE ON server_access FOR EACH ROW EXECUTE FUNCTION pufferblow_ledger()"),
    ("blocked_ips", "pufferblow_ledger_ips", "AFTER INSERT OR DELETE ON blocked_ips FOR EACH ROW EXECUTE FUNCTION pufferblow_ledger()"),
)

#: (table, constraint name, definition). Added as NOT VALID: new writes are checked, rows from before are not rescanned.
CONSTRAINTS = (
    ("users", "pufferblow_users_membership_status_check", f"CHECK (membership_status IN ({', '.join(repr(v) for v in MEMBERSHIP_VALUES)}))"),
    ("server_invites", "pufferblow_invites_uses_check", "CHECK (uses >= 0 AND (max_uses IS NULL OR uses <= max_uses))"),
)


def apply(bind) -> None:
    """Install or refresh the rules and the ledger triggers (PostgreSQL only; a table that is not there yet is skipped)."""
    if bind.dialect.name != "postgresql":
        return
    tables = set(sa.inspect(bind).get_table_names())
    if "security_ledger" not in tables:
        return  # the tables come first (create_all at boot); the next start installs the rest
    # The rows are written by triggers, which cannot use the application's default.
    bind.execute(sa.text("ALTER TABLE security_ledger ALTER COLUMN at SET DEFAULT now()"))
    for sql in FUNCTIONS.values():
        bind.execute(sa.text(sql))
    for table, name, definition in TRIGGERS:
        if table not in tables:
            continue
        bind.execute(sa.text(f"DROP TRIGGER IF EXISTS {name} ON {table}"))
        bind.execute(sa.text(f"CREATE TRIGGER {name} {definition}"))
    for table, name, definition in CONSTRAINTS:
        if table not in tables:
            continue
        exists = bind.execute(sa.text("SELECT 1 FROM pg_constraint WHERE conname = :n"), {"n": name}).first()
        if exists is None:
            bind.execute(sa.text(f"ALTER TABLE {table} ADD CONSTRAINT {name} {definition} NOT VALID"))
