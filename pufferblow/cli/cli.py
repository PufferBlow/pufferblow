"""PufferBlow CLI entrypoint.

The CLI was previously built with `typer`. Typer carried Click as a
transitive dep, plus its own decorator runtime, plus Rich for help
rendering — a few hundred KB of wheels for a flat dispatcher over 10
subcommands. We now ship argparse, which is in the stdlib and does
the same job.

Command surface is unchanged:

    pufferblow version
    pufferblow setup            [--setup-server | --update-server
                                 | --setup-media-sfu | --backup]
    pufferblow serve            [--log-level N] [--debug] [--dev]
    pufferblow migrate          [--check]
    pufferblow doctor
    pufferblow backup now
    pufferblow backup mirror
    pufferblow storage setup
    pufferblow storage test
    pufferblow storage migrate  --source-provider X --target-provider Y
                                [--batch-size N] [--dry-run]

Each leaf command is implemented in `pufferblow.cli.commands.*`; this
module is purely the parser + dispatcher. Implementation functions
take plain keyword arguments now (no `typer.Option` defaults) so they
remain importable from tests without a CLI runner.
"""

from __future__ import annotations

import argparse
import sys
from typing import Sequence


_LOG_LEVEL_HELP = "Log level [0=INFO, 1=DEBUG, 2=ERROR, 3=CRITICAL]."


def _build_parser() -> argparse.ArgumentParser:
    """Construct the full parser tree once.

    Kept as a function (not module-level) so importing this module
    doesn't side-effect a parser into existence — the banner-emitting
    `run()` only builds it when something actually invokes the CLI.
    """
    parser = argparse.ArgumentParser(
        prog="pufferblow",
        description="PufferBlow server command line interface.",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="<command>")
    subparsers.required = True

    # ── version ──────────────────────────────────────────────────
    subparsers.add_parser("version", help="Display the installed PufferBlow version.")

    # ── setup ────────────────────────────────────────────────────
    setup_p = subparsers.add_parser(
        "setup",
        help="Configure database, server metadata, and owner account.",
    )
    # `add_mutually_exclusive_group` would be the strict-correct
    # answer here, but the existing setup_command() does its own
    # multi-flag validation and shows a friendlier error message;
    # keep the validation in one place by accepting them all as
    # independent booleans and letting setup_command sort it out.
    setup_p.add_argument(
        "--setup-server",
        dest="is_setup_server",
        action="store_true",
        help="Only create initial server metadata.",
    )
    setup_p.add_argument(
        "--update-server",
        dest="is_update_server",
        action="store_true",
        help="Update existing server metadata (name, description, welcome message).",
    )
    setup_p.add_argument(
        "--setup-media-sfu",
        dest="is_setup_media_sfu",
        action="store_true",
        help="Only update the shared Pufferblow config [media-sfu] section.",
    )
    setup_p.add_argument(
        "--backup",
        dest="is_setup_backup",
        action="store_true",
        help="Configure database backup settings (file dump or mirror).",
    )
    setup_p.add_argument(
        "--setup-memcache",
        dest="is_setup_memcache",
        action="store_true",
        help="Configure the [memcache] host/port the server connects to.",
    )

    # ── serve ────────────────────────────────────────────────────
    serve_p = subparsers.add_parser("serve", help="Start the API server.")
    serve_p.add_argument(
        "--log-level",
        dest="log_level",
        type=int,
        default=0,
        help=_LOG_LEVEL_HELP,
    )
    serve_p.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug traces and diagnostics.",
    )
    serve_p.add_argument(
        "--dev",
        action="store_true",
        help="Run with uvicorn auto-reload for development.",
    )

    # ── migrate ──────────────────────────────────────────────────
    migrate_p = subparsers.add_parser(
        "migrate",
        help="Apply database schema changes (idempotent) or report drift.",
    )
    migrate_p.add_argument(
        "--check",
        action="store_true",
        help="Report schema drift without applying it. Exits 1 if drift exists.",
    )
    migrate_p.add_argument(
        "--backfill-search",
        action="store_true",
        help=(
            "After applying schema, walk every existing message row and "
            "populate its `search_tokens` tsvector from the decrypted "
            "plaintext. Required on long-lived instances upgrading to the "
            "ranked-search feature — new messages auto-populate, but rows "
            "that existed before the upgrade are invisible to search until "
            "this runs. Idempotent; safe to re-run."
        ),
    )
    migrate_p.add_argument(
        "--backfill-batch-size",
        type=int,
        default=500,
        help=(
            "How many messages per transaction when backfilling search "
            "tokens (default 500). Larger batches finish faster but hold "
            "row locks longer."
        ),
    )

    # ── doctor ───────────────────────────────────────────────────
    subparsers.add_parser(
        "doctor",
        help="Read-only health check across DB, schema, storage, and config.",
    )

    # ── backup (group) ───────────────────────────────────────────
    backup_p = subparsers.add_parser(
        "backup",
        help="On-demand database backup operations.",
    )
    backup_sub = backup_p.add_subparsers(dest="backup_command", metavar="<subcommand>")
    backup_sub.required = True
    backup_sub.add_parser("now", help="Run pg_dump immediately.")
    backup_sub.add_parser(
        "mirror",
        help="Mirror the database to BACKUP_MIRROR_DSN immediately.",
    )

    # ── storage (group) ──────────────────────────────────────────
    storage_p = subparsers.add_parser(
        "storage",
        help="Manage server storage backends.",
    )
    storage_sub = storage_p.add_subparsers(dest="storage_command", metavar="<subcommand>")
    storage_sub.required = True
    storage_sub.add_parser("setup", help="Interactive storage backend setup wizard.")
    storage_sub.add_parser("test", help="Test the currently configured storage backend.")

    storage_migrate_p = storage_sub.add_parser(
        "migrate",
        help="Migrate files between configured storage backends.",
    )
    storage_migrate_p.add_argument(
        "--source-provider",
        dest="source_provider",
        required=True,
        help="Source provider ('local' or 's3').",
    )
    storage_migrate_p.add_argument(
        "--target-provider",
        dest="target_provider",
        required=True,
        help="Target provider ('local' or 's3').",
    )
    storage_migrate_p.add_argument(
        "--batch-size",
        dest="batch_size",
        type=int,
        default=10,
        help="How many files to migrate per batch.",
    )
    storage_migrate_p.add_argument(
        "--dry-run",
        dest="dry_run",
        action="store_true",
        help="Analyze only, do not migrate files.",
    )

    return parser


def _dispatch(args: argparse.Namespace) -> int:
    """Route a parsed namespace to its implementation.

    Returns an exit code (0 on success). All implementations may
    raise SystemExit to signal a non-zero exit; we catch it here so
    `_dispatch` always returns an int and tests can introspect it
    cleanly.
    """
    try:
        if args.command == "version":
            from rich import print as rprint

            import pufferblow.core.constants as constants

            rprint(f"[bold cyan]pufferblow [reset]{constants.VERSION}")
            return 0

        if args.command == "setup":
            from pufferblow.cli.commands.setup import setup_command

            setup_command(
                is_setup_server=args.is_setup_server,
                is_update_server=args.is_update_server,
                is_setup_media_sfu=args.is_setup_media_sfu,
                is_setup_backup=args.is_setup_backup,
                is_setup_memcache=args.is_setup_memcache,
            )
            return 0

        if args.command == "serve":
            from pufferblow.cli.commands.serve import serve_command

            serve_command(log_level=args.log_level, debug=args.debug, dev=args.dev)
            return 0

        if args.command == "migrate":
            from pufferblow.cli.commands.migrate import migrate_command

            migrate_command(
                check=args.check,
                backfill_search=args.backfill_search,
                backfill_batch_size=args.backfill_batch_size,
            )
            return 0

        if args.command == "doctor":
            from pufferblow.cli.commands.doctor import doctor_command

            doctor_command()
            return 0

        if args.command == "backup":
            from pufferblow.cli.commands.backup import (
                backup_mirror_command,
                backup_now_command,
            )

            if args.backup_command == "now":
                backup_now_command()
            elif args.backup_command == "mirror":
                backup_mirror_command()
            return 0

        if args.command == "storage":
            from pufferblow.cli.commands.storage import (
                migrate_storage_command,
                setup_storage_command,
                test_storage_command,
            )

            if args.storage_command == "setup":
                setup_storage_command()
            elif args.storage_command == "test":
                test_storage_command()
            elif args.storage_command == "migrate":
                migrate_storage_command(
                    source_provider=args.source_provider,
                    target_provider=args.target_provider,
                    batch_size=args.batch_size,
                    dry_run=args.dry_run,
                )
            return 0

        # Unreachable because subparsers.required = True forces a
        # command name, but argparse can't prove that to the type
        # checker.
        return 0
    except SystemExit as exc:
        # SystemExit's `code` is `int | str | None`. Normalize.
        if isinstance(exc.code, int):
            return exc.code
        if exc.code is None:
            return 0
        return 1


def run() -> None:
    """CLI entrypoint registered as the `pufferblow` console script."""
    argv = sys.argv[1:]
    should_render_banner = bool(argv) and argv[0] not in (
        "-h",
        "--help",
    )
    if should_render_banner:
        import pufferblow.core.constants as constants

        constants.banner()

    parser = _build_parser()
    args = parser.parse_args(argv)
    sys.exit(_dispatch(args))


def invoke(argv: Sequence[str]) -> tuple[int, str, str]:
    """Programmatic CLI entry — used by tests.

    Returns `(exit_code, stdout, stderr)`. Captures both streams so
    assertions can match against either: most CLI output now goes
    through loguru's stderr sink, but some commands still hand output
    to `rich.console.Console.print` which writes to stdout. Keeping
    both available means tests don't have to know which sink a given
    line ended up on.
    """
    import contextlib
    import io

    parser = _build_parser()
    try:
        args = parser.parse_args(list(argv))
    except SystemExit as exc:
        # `parser.parse_args` calls sys.exit on bad input. We still
        # want to return an `(exit_code, "", "")` tuple rather than
        # propagate, so the test path looks like a normal CLI run.
        code = exc.code if isinstance(exc.code, int) else 2
        return code, "", ""

    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        exit_code = _dispatch(args)
    return exit_code, out.getvalue(), err.getvalue()


if __name__ == "__main__":
    run()
