"""On-demand database backup commands.

The server already runs scheduled `pg_dump` and optional mirror jobs
through `background_tasks_manager`. `pufferblow backup now` triggers
the same code path on demand, useful for:

  - "Take a backup before I touch this" moments
  - Cron / external automation that wants to pin its own schedule
    instead of the in-server scheduler
  - CI smoke tests that want to verify pg_dump is reachable from
    the deployment container

Both subcommands reuse the manager's existing methods so behavior
matches the background path byte-for-byte. We don't reimplement the
pg_dump invocation here.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from loguru import logger


def _ui_error(message: str) -> None:
    logger.error(message)


def _load_manager():
    """Bring up the runtime far enough to access background_tasks_manager."""
    from pufferblow.api.config.config_handler import ConfigHandler
    from pufferblow.cli.common import (
        configure_cli_logging,
        ensure_database_exists,
        load_config_or_exit,
        load_runtime,
    )

    configure_cli_logging()
    load_config_or_exit()
    database_uri = ConfigHandler().resolve_database_uri()
    if not database_uri:
        _ui_error("No bootstrap database URI found. Run `pufferblow setup` first.")
        raise typer.Exit(code=1)
    ensure_database_exists(database_uri)
    load_runtime(database_uri=database_uri, setup_tables=False)

    from pufferblow.core.bootstrap import api_initializer

    if api_initializer.background_tasks_manager is None:
        _ui_error("Background task manager is unavailable.")
        raise typer.Exit(code=1)
    return api_initializer.background_tasks_manager


def backup_now_command() -> None:
    """Run pg_dump against the configured database immediately."""
    manager = _load_manager()
    config = manager.config

    backup_path = Path(getattr(config, "BACKUP_PATH", "~/.pufferblow/backups")).expanduser()

    try:
        asyncio.run(manager.create_database_backup())
    except FileNotFoundError as exc:
        # pg_dump not installed on PATH — the most common failure
        # mode, especially in lean containers. Tell the operator
        # what's missing rather than dumping the raw OSError.
        _ui_error(
            f"pg_dump is not available on PATH ({exc}). Install the postgresql-client package."
        )
        raise typer.Exit(code=1)
    except Exception as exc:
        _ui_error(f"Backup failed: {exc}")
        raise typer.Exit(code=1)

    logger.success("Backup written.")
    logger.info("  location={path}", path=str(backup_path))
    logger.info(
        "  rotation_keep_last={n}",
        n=getattr(config, "BACKUP_MAX_FILES", 7),
    )


def backup_mirror_command() -> None:
    """Mirror the database to the configured BACKUP_MIRROR_DSN target."""
    manager = _load_manager()
    config = manager.config

    mirror_dsn = getattr(config, "BACKUP_MIRROR_DSN", None)
    if not mirror_dsn:
        _ui_error(
            "No mirror DSN configured. Run `pufferblow setup --backup` and choose 'mirror' mode."
        )
        raise typer.Exit(code=1)

    try:
        asyncio.run(manager.mirror_database())
    except FileNotFoundError as exc:
        _ui_error(
            f"pg_dump / psql missing on PATH ({exc}). Install the postgresql-client package."
        )
        raise typer.Exit(code=1)
    except Exception as exc:
        _ui_error(f"Mirror failed: {exc}")
        raise typer.Exit(code=1)

    logger.success("Database mirrored to secondary.")
