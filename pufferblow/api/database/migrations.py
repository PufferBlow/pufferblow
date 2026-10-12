"""Automatic Alembic migrations, run at boot — never a manual CLI step.

Pufferblow's schema history up to this point was managed by hand-rolled,
idempotent `_apply_*_migration` methods on `DatabaseHandler` (inspect the
live schema, `ALTER TABLE ... ADD COLUMN` if missing). Those stay exactly
as they are — they already ran on every real deployed instance and ARE
the system of record for that history. From here on, new schema changes
are added as Alembic revisions under `migrations/versions/` instead, and
this module is what applies them: `load_database()` in `core/bootstrap.py`
calls `run_migrations()` right after `DatabaseHandler` finishes its own
setup, on every boot. An operator never runs `alembic upgrade head`
themselves.

The baseline revision (`migrations/versions/0001_baseline.py`) is an
intentional no-op: by the time this runs, `DatabaseHandler.__init__` has
already brought the schema to its pre-Alembic "current" state via
`create_all` + the hand-rolled migrations, so the first Alembic revision
has nothing left to do — it only stamps `alembic_version` so the chain
has a starting point for real changes to build on.
"""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from loguru import logger

#: `pufferblow/pufferblow/migrations` — ships inside the package itself
#: (not at the repo root) so the path resolves the same way whether this
#: runs from a checked-out repo or an installed package, regardless of
#: the process's current working directory.
_MIGRATIONS_DIR = Path(__file__).resolve().parents[2] / "migrations"


def _build_config(database_url: str) -> Config:
    config = Config()
    config.set_main_option("script_location", str(_MIGRATIONS_DIR))
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def run_migrations(database_engine) -> None:
    """Bring the schema to the latest Alembic revision using the app's own engine.

    Reuses the given engine's connection (via `config.attributes["connection"]`,
    the standard Alembic recipe for embedding migrations in an app that
    already owns an engine) instead of opening a second connection pool.

    Failures are logged and swallowed rather than raised — a transient
    migration hiccup must not crash the whole server at boot, matching the
    fail-soft philosophy the existing `_apply_*_migration` methods already
    use. Operators who want a hard failure on migration drift have
    `pufferblow migrate --check` for that.
    """
    config = _build_config(str(database_engine.url))
    try:
        with database_engine.connect() as connection:
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
    except Exception as exc:
        logger.warning("Alembic migration skipped due to error: {err}", err=str(exc))
