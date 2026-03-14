"""Top-level package exports."""

from __future__ import annotations


def run() -> None:
    """Lazy CLI entrypoint to avoid importing CLI-only dependencies on package import."""
    from pufferblow.cli.cli import run as cli_run

    cli_run()
