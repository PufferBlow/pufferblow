"""PufferBlow CLI entrypoint.

This module wires command groups and delegates implementation details to
specialized command modules.
"""

from __future__ import annotations

import sys

import typer

cli = typer.Typer(
    help="PufferBlow server command line interface.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
storage_cli = typer.Typer(help="Manage server storage backends.")
cli.add_typer(storage_cli, name="storage")


@cli.command("version")
def version_command() -> None:
    """Display the installed PufferBlow version."""
    from rich import print

    import pufferblow.core.constants as constants

    print(f"[bold cyan]pufferblow [reset]{constants.VERSION}")


@cli.command("setup")
def setup_command_entry(
    is_setup_server: bool = typer.Option(
        False, "--setup-server", help="Only create initial server metadata."
    ),
    is_update_server: bool = typer.Option(
        False,
        "--update-server",
        help="Update existing server metadata (name, description, welcome message).",
    ),
    is_setup_media_sfu: bool = typer.Option(
        False,
        "--setup-media-sfu",
        help="Only update the shared Pufferblow config [media-sfu] section.",
    ),
) -> None:
    """Run the setup command with lazy imports."""
    from pufferblow.cli.commands.setup import setup_command

    setup_command(
        is_setup_server=is_setup_server,
        is_update_server=is_update_server,
        is_setup_media_sfu=is_setup_media_sfu,
    )


@cli.command("serve")
def serve_command_entry(
    log_level: int = typer.Option(
        0,
        "--log-level",
        help="Log level [0=INFO, 1=DEBUG, 2=ERROR, 3=CRITICAL].",
    ),
    debug: bool = typer.Option(
        False, "--debug", help="Enable debug traces and diagnostics."
    ),
    dev: bool = typer.Option(
        False, "--dev", help="Run with uvicorn auto-reload for development."
    ),
) -> None:
    """Run the serve command with lazy imports."""
    from pufferblow.cli.commands.serve import serve_command

    serve_command(log_level=log_level, debug=debug, dev=dev)


@storage_cli.command("setup")
def setup_storage_command_entry() -> None:
    """Run storage setup with lazy imports."""
    from pufferblow.cli.commands.storage import setup_storage_command

    setup_storage_command()


@storage_cli.command("test")
def test_storage_command_entry() -> None:
    """Run storage tests with lazy imports."""
    from pufferblow.cli.commands.storage import test_storage_command

    test_storage_command()


@storage_cli.command("migrate")
def migrate_storage_command_entry(
    source_provider: str = typer.Option(
        ..., "--source-provider", help="Source provider ('local' or 's3')."
    ),
    target_provider: str = typer.Option(
        ..., "--target-provider", help="Target provider ('local' or 's3')."
    ),
    batch_size: int = typer.Option(
        10, "--batch-size", help="How many files to migrate per batch."
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Analyze only, do not migrate files."
    ),
) -> None:
    """Run storage migration with lazy imports."""
    from pufferblow.cli.commands.storage import migrate_storage_command

    migrate_storage_command(
        source_provider=source_provider,
        target_provider=target_provider,
        batch_size=batch_size,
        dry_run=dry_run,
    )


def run() -> None:
    """Run the CLI application."""
    argv = sys.argv[1:]
    should_render_banner = not any(
        flag in argv for flag in ("--help", "--show-completion", "--install-completion")
    )
    if should_render_banner:
        import pufferblow.core.constants as constants

        constants.banner()
    cli()


if __name__ == "__main__":
    run()

