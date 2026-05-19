"""Database schema migration command.

Pufferblow does not use Alembic. Schema is shipped via SQLAlchemy
declarative tables plus a small set of idempotent ALTER scripts in
`database_handler.setup_tables` (the appearance-column migration, the
blocked_ips counter migration, etc.). Every `pufferblow serve` run
calls `setup_tables` during boot, so a single-process deploy with
restart-on-upgrade already gets the migration "for free".

This command exists for the cases where boot-time migration is not
what you want:

  - Multi-replica deploys where one box should apply schema before
    the others start serving traffic.
  - A nervous operator who wants to apply schema changes during a
    maintenance window, verify, and only then start the server.
  - CI pipelines that need to assert "the model and the DB agree"
    without booting a full app.

`migrate --check` reports drift between SQLAlchemy's declared
metadata and the live database (missing tables, missing columns) but
does not apply anything. The exit code is 0 if there is no drift, 1
otherwise — useful as a deploy gate.
"""

from __future__ import annotations

import typer
from rich.panel import Panel
from rich.table import Table


def _console():
    from pufferblow.cli.common import console

    return console


def _ui_error(message: str) -> None:
    _console().print(f"[bold red]{message}[/bold red]")


def _detect_schema_drift() -> tuple[list[str], list[tuple[str, str]]]:
    """Return (missing_tables, missing_columns) by comparing models to DB.

    `missing_columns` is a list of (table_name, column_name) tuples for
    columns the SQLAlchemy declarative metadata declares but that are
    not present on the live database. We don't report columns the DB
    has but metadata doesn't — those are leftover state, not drift the
    server cares about.
    """
    from sqlalchemy import inspect

    from pufferblow.api.database.tables.declarative_base import Base
    from pufferblow.core.bootstrap import api_initializer

    inspector = inspect(api_initializer.database_handler.database_engine)
    live_tables = set(inspector.get_table_names())

    missing_tables: list[str] = []
    missing_columns: list[tuple[str, str]] = []

    for table in Base.metadata.sorted_tables:
        if table.name not in live_tables:
            missing_tables.append(table.name)
            continue
        try:
            live_cols = {col["name"] for col in inspector.get_columns(table.name)}
        except Exception:
            # If we can't introspect a single table, skip it rather than
            # erroring the whole drift check.
            continue
        for column in table.columns:
            if column.name not in live_cols:
                missing_columns.append((table.name, column.name))

    return missing_tables, missing_columns


def migrate_command(
    check: bool = typer.Option(
        False,
        "--check",
        help="Report schema drift without applying it. Exits non-zero if drift exists.",
    ),
) -> None:
    """Apply database schema (idempotent) or report drift in --check mode."""
    from pufferblow.cli.common import (
        configure_cli_logging,
        ensure_database_exists,
        load_config_or_exit,
        load_runtime,
    )

    configure_cli_logging()
    console = _console()

    config = load_config_or_exit()
    database_uri = config.DATABASE_URI if hasattr(config, "DATABASE_URI") else None
    if not database_uri:
        from pufferblow.api.config.config_handler import ConfigHandler

        database_uri = ConfigHandler().resolve_database_uri()
    if not database_uri:
        _ui_error("No bootstrap database URI found. Run `pufferblow setup` first.")
        raise typer.Exit(code=1)

    ensure_database_exists(database_uri)
    # `setup_tables=False` because we don't want load_runtime to
    # implicitly apply schema during the drift check. The migrate
    # command should make the apply step explicit.
    load_runtime(database_uri=database_uri, setup_tables=False)

    missing_tables, missing_columns = _detect_schema_drift()

    if check:
        if not missing_tables and not missing_columns:
            console.print("[green]Schema is up to date.[/green] No drift detected.")
            raise typer.Exit(code=0)

        table = Table(title="Schema drift", show_header=True, header_style="bold")
        table.add_column("Kind", style="cyan")
        table.add_column("Target")
        for name in missing_tables:
            table.add_row("missing table", name)
        for table_name, column_name in missing_columns:
            table.add_row("missing column", f"{table_name}.{column_name}")
        console.print(table)
        console.print(
            "\n[yellow]Run `pufferblow migrate` (no --check) to apply.[/yellow]"
        )
        raise typer.Exit(code=1)

    # Non-check path: apply. Reuses the same setup_tables() that runs
    # on `pufferblow serve` boot, so behavior is byte-for-byte the
    # same as what an unattended upgrade would do.
    from pufferblow.api.database.tables.declarative_base import Base
    from pufferblow.core.bootstrap import api_initializer

    try:
        api_initializer.database_handler.setup_tables(Base)
    except Exception as exc:
        _ui_error(f"Migration failed: {exc}")
        raise typer.Exit(code=1)

    summary_lines: list[str] = []
    if missing_tables:
        summary_lines.append(f"[green]Created tables:[/green] {', '.join(missing_tables)}")
    if missing_columns:
        joined = ", ".join(f"{t}.{c}" for t, c in missing_columns)
        summary_lines.append(f"[green]Added columns:[/green] {joined}")
    if not summary_lines:
        summary_lines.append("[green]Schema already up to date.[/green]")
        summary_lines.append("[dim]Idempotent post-migrations (appearance, blocked IP counters, backfills) ran successfully.[/dim]")

    console.print(
        Panel.fit(
            "\n".join(summary_lines),
            title="[bold green]Migration Complete[/bold green]",
            border_style="green",
        )
    )
