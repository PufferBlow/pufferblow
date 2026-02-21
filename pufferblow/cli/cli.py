"""PufferBlow CLI entrypoint.

This module wires command groups and delegates implementation details to
specialized command modules.
"""

from __future__ import annotations

import typer
from rich import print

import pufferblow.core.constants as constants
from pufferblow.cli.commands.serve import serve_command
from pufferblow.cli.commands.setup import setup_command
from pufferblow.cli.commands.storage import (
    migrate_storage_command,
    setup_storage_command,
    test_storage_command,
)

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
    print(f"[bold cyan]pufferblow [reset]{constants.VERSION}")


cli.command("setup")(setup_command)
cli.command("serve")(serve_command)
storage_cli.command("setup")(setup_storage_command)
storage_cli.command("test")(test_storage_command)
storage_cli.command("migrate")(migrate_storage_command)


def run() -> None:
    """Run the CLI application."""
    constants.banner()
    cli()


if __name__ == "__main__":
    run()

