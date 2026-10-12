"""Alembic environment for Pufferblow.

Two ways this runs:

1. **At boot, automatically** — `pufferblow.api.database.migrations.run_migrations`
   builds a `Config` with no `.ini` file, puts a live `Connection` from the
   app's own engine in `config.attributes["connection"]`, and calls
   `command.upgrade(config, "head")`. `run_migrations_online` below picks
   that connection up instead of opening a second one.
2. **From the CLI during development** (`alembic revision --autogenerate`,
   or a manual `alembic upgrade head` against a throwaway DB) — there is
   no live connection in `config.attributes`, so this falls back to
   building its own engine from `sqlalchemy.url` the normal Alembic way.

`target_metadata` is the same `Base` every table in
`pufferblow/api/database/tables/` is declared against, so autogenerate
diffs against the real current model state.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from pufferblow.api.database.tables.declarative_base import Base

# Make every table module register itself on `Base.metadata` before
# autogenerate reads it. Importing the tables *package* isn't enough on
# its own unless each module is actually imported somewhere; importing
# `database_handler` (which imports every table module) guarantees it.
import pufferblow.api.database.database_handler  # noqa: F401,E402

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Emit SQL to stdout without a live DB connection (`alembic upgrade head --sql`)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Apply migrations against a live connection."""
    connection = config.attributes.get("connection")

    if connection is not None:
        # Boot-time path: reuse the app's own engine/connection.
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
        return

    # CLI path: no connection was handed to us, build our own engine. The
    # repo-root alembic.ini deliberately leaves sqlalchemy.url blank, so
    # fall back to the same resolver the app itself uses (config.toml, then
    # PUFFERBLOW_DATABASE_URI) rather than inventing a second one.
    section = config.get_section(config.config_ini_section, {})
    if not section.get("sqlalchemy.url"):
        from pufferblow.api.config.config_handler import ConfigHandler

        resolved = ConfigHandler().resolve_database_uri()
        if resolved:
            section["sqlalchemy.url"] = resolved

    connectable = engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
