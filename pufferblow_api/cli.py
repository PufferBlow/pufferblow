import sys
import typer

from rich import print
from loguru import logger
from rich.console import Console

from pufferblow_api.src.logger.logger import (
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

# Log messages
from pufferblow_api.src.logger.msgs import (
    errors
)

# ConfigHandler
from pufferblow_api.src.config.config_handler import ConfigHandler

# Models
from pufferblow_api.src.models.pufferblow_api_config_model import PufferBlowAPIconfig

# Init cli
cli = typer.Typer()

# Init console
console = Console()

# Pre-init the config handler and the config model
# TODO: Find a better to do this
config_handler = ConfigHandler() 

if not config_handler.check_config():
    logger.error(errors.ERROR_NO_CONFIG_FILE_FOUND(config_handler.config_file_path))
    sys.exit(1)

pufferblow_api_config = PufferBlowAPIconfig(
    config=config_handler.load_config()
)

@cli.command()
def version():
    """ PufferBlow's API version """
    print(f"[bold cyan] Version [italic white]{constants.VERSION}")

@cli.command()
def setup():
    """ setup pufferblow's API """
    pass

@cli.command()
def serve():
    """ Serve PufferBlow's API """
    if pufferblow_api_config.SUPABASE_URL == "<your supabase url>" and pufferblow_api_config.SUPABASE_KEY == "<your supabase key>":
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
    logger.add(pufferblow_api_config.LOGS_PATH, rotation="10 MB")

    OPTIONS = {
        "bind": f"{pufferblow_api_config.API_HOST}:{pufferblow_api_config.API_PORT}",
        "workers": WORKERS(pufferblow_api_config.WORKERS),
        "timeout": 86400, # 24 hours
        "keepalive": 86400, # 24 hours
        "accesslog": "-",
        "errorlog": "-",
        "worker_class": "uvicorn.workers.UvicornWorker",
        "logger_class": StubbedGunicornLogger
    }

    StandaloneApplication(api, OPTIONS).run()

def run() -> None: cli()
