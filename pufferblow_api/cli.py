import os
import sys
import typer

from rich import print
from rich.console import Console

from pufferblow_api import constants
from pufferblow_api.pufferblow_api import run
from pufferblow_api.src.models.tests_model import Test
from pufferblow_api.src.conf_file_reader.load_config import load_config

# from pufferblow_api.tests.test_user_signup import test_user_signup

# Init cli
CLI = typer.Typer()

# Init console
CONSOLE = Console()

@CLI.command()
def version():
    """ PufferBlow's API version """
    print(f"[bold cyan] Version [italic white]{constants.VERSION}")

# @CLI.command()
# def tests():
#     """ Runs all the tests """
#     tests = [
#         test_user_signup
#     ]

#     with CONSOLE.status("[bold green] Running tests") as status:
#         for test in tests:
#             _test = Test(test.__name__, tests.index(test))
#             _test.run(test)

#             CONSOLE.log(f"[bold yellow] `{test.__name__}` {_test.message}")

@CLI.command()
def serve():
    """ Serves the API on the passed host and port """
    CONFIG = load_config()

    if CONFIG["supabase"][0]["supabase_url"] == "<your supabase url>" and CONFIG["supabase"][1]["supabase_key"] == "<your supabase key>":
        print(f"[bold red] [  ?  ] [bold white] Config error: please edit the [italic yellow]`supabase_url`[/][bold white] and [italic yellow]`supabase_key`[/][bold white] feilds in [bold cyan]{constants.PUFFERBLOW_CONFIG_PATH}[white]")
        sys.exit(1)
    
    run()

main = CLI()

if __name__ == "__main__":
    main()
