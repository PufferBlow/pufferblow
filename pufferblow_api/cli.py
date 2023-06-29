import sys
import typer

from rich import print
from loguru import logger
from rich.console import Console

from pufferblow_api.src.utils.logger import (
    InterceptHandler,
    logging,
    StandaloneApplication,
    StubbedGunicornLogger,
    LOG_LEVEL,
    WORKERS,
    JSON_LOGS,
)
from pufferblow_api import constants
from pufferblow_api.pufferblow_api import api
from pufferblow_api.src.models.pufferblow_api_config_model import PufferBlowAPIConfig

# Init cli
cli = typer.Typer()

# Init console
CONSOLE = Console()

# Get config data
PUFFERBLOW_API_CONFIG = PufferBlowAPIConfig()

@cli.command()
def version():
    """ PufferBlow's API version """
    print(f"[bold cyan] Version [italic white]{constants.VERSION}")

@cli.command()
def serve():
    """ Serves the API on the passed host and port """
    if PUFFERBLOW_API_CONFIG.SUPABASE_URL == "<your supabase url>" and PUFFERBLOW_API_CONFIG.SUPABASE_KEY == "<your supabase key>":
        print(f"[bold red] [  ?  ] [bold white] Config error: please edit the [italic yellow]`supabase_url`[/][bold white] and [italic yellow]`supabase_key`[/][bold white] feilds in [bold cyan]{constants.PUFFERBLOW_CONFIG_PATH}[white]")
        sys.exit(1)
    
    INTERCEPT_HANDLER = InterceptHandler()
    # logging.basicConfig(handlers=[INTERCEPT_HANDLER], level=LOG_LEVEL)
    # logging.root.handlers = [INTERCEPT_HANDLER]
    logging.root.setLevel(LOG_LEVEL)

    SEEN = set()

    for name in [
        *logging.root.manager.loggerDict.keys(),
        "gunicorn",
        "gunicorn.access",
        "gunicorn.error",
        "uvicorn",
        "uvicorn.access",
        "uvicorn.error",
    ]:
        if name not in SEEN:
            SEEN.add(name.split(".")[0])
            logging.getLogger(name).handlers = [INTERCEPT_HANDLER]

    logger.configure(handlers=[{"sink": sys.stdout, "serialize": JSON_LOGS}])
    logger.add(PUFFERBLOW_API_CONFIG.LOGS_PATH, rotation="10 MB")
    
    OPTIONS = {
        "bind": f"{PUFFERBLOW_API_CONFIG.API_HOST}:{PUFFERBLOW_API_CONFIG.API_PORT}",
        "workers": WORKERS(PUFFERBLOW_API_CONFIG.WORKERS),
        "timeout": PUFFERBLOW_API_CONFIG.CONNECTION_TIMEOUT,
        "accesslog": "-",
        "errorlog": "-",
        "worker_class": "uvicorn.workers.UvicornWorker",
        "logger_class": StubbedGunicornLogger
    }

    StandaloneApplication(api, OPTIONS).run()

main = cli()

if __name__ == "__main__":
    main()
