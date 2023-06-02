import os
import sys
import typer

from rich import print
from rich.console import Console

from pufferblow_api import constants
from pufferblow_api.pufferblow_api import run
from pufferblow_api.src.conf_file_reader.load_config import load_config

# Init cli
CLI = typer.Typer()

# Init console
CONSOLE = Console()

@CLI.command()
def version():
    """ PufferBlow's API version """
    print(f"[bold cyan] Version [italic white]{constants.VERSION}")

@CLI.command()
def tests():
    """ Runs all the tests """
    pass

@CLI.command()
def serve():
    """ Serves the API on the passed host and port """
    CONFIG = load_config()

    if CONFIG["cassandra"][2]["username"] == "<your username>" and CONFIG["cassandra"][3]["password"] == "<your password>":
        print(f"[bold red] [  ?  ] [bold white] Config error: please edit the [italic yellow]`username`[/][bold white] and [italic yellow]`password`[/][bold white] feilds in [bold cyan]{constants.PUFFERBLOW_CONFIG_PATH}[white]")
        sys.exit(1)
    
    run()

main = CLI()

if __name__ == "__main__":
    main()
