#!/usr/bin/python

import os
import sys
import typer
import subprocess

from rich.console import Console

# Init cli
cli = typer.Typer()

# Init console
console = Console()

def install_libs_packages() -> None:
    """ Installs the sphinx-build package """
    command_process = subprocess.run(
        "poetry install",
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
        f"cd {docs_path} && poetry run make html",
        shell=True,
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )

    stdout = command_process.stdout.decode()
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
    docs_path = ""

    pwd = os.path.abspath(os.getcwd())
    if not pwd.endswith("pufferblow-api/docs") and not "scripts" in pwd:
        docs_path = f"{pwd}/docs"
    if not pwd.endswith("pufferblow-api/docs") and "scripts" in pwd:
        docs_path = f"{pwd.replace('scripts', 'docs')}"
    
    # Check if the `docs_path` is really the docs dir
    if not "conf.py" in os.listdir(docs_path):
        console.log("[bold red] [ - ] [bold white]Faild to locate the docs folder please change directory to it and try again.")
    
    console.log("[bold green] [ + ] [bold white]Building docs...")
    build_docs(
        docs_path=docs_path
    )

def run() -> None: cli()

if __name__ == "__main__":
    run()
