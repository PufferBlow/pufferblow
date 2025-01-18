#!/usr/bin/python

import sys
import typer
import subprocess

from pathlib import Path
from rich.console import Console

# Init cli
cli = typer.Typer()

# Init console
console = Console()
console._log_render.omit_repeated_times = False

# Get the script directory
script_dir = Path(__file__).parent

# Construct the docs path
docs_path = script_dir.parent / "docs"

def install_libs_packages() -> None:
    """ Installs the sphinx-build package """
    command_process = subprocess.run(
        "pip install sphinx-autobuild sphinx-book-theme",
        shell=True,
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE
    )

    stderr = command_process.stderr.decode()

    if len(stderr) > 0:
        console.log(f"[bold red][ - ] [bold white] the following error raised when installing packages:\n{stderr}")
        sys.exit(1)

def build_docs(docs_path: str) -> None:
    """ Builds docs """
    command_process = subprocess.run(
        f"cd {docs_path} && make html",
        shell=True,
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )

    stderr = command_process.stderr.decode()

    if "sphinx-build not found" in stderr:
        console.log("[bold red][ - ] [bold green] `sphinx-build`[bold white] is not installed. Installing...")

        install_libs_packages() # May exit due to errors while installing

        build_docs(
            docs_path=docs_path
        )

    return

@cli.command()
def build() -> None:
    """ Builds docs """
    with console.status("Building docs...") as _:
        build_docs(
            docs_path=docs_path
        )

    console.log(f"[bold green] [ + ] [reset]Docs built in: [bold yellow]'{docs_path}/_static'")

@cli.command()
def serve() -> None:
    """ Serves the docs """
    command = f"cd {docs_path} && sphinx-autobuild . _build"

    try:
        subprocess.run(command, shell=True)
    except KeyboardInterrupt:
        exit(0)

def run() -> None: cli()

if __name__ == "__main__":
    run()
