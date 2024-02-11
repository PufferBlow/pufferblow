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
    WORKERS,
    JSON_LOGS,
)
from pufferblow_api import constants
from pufferblow_api.api import api

# Log messages
from pufferblow_api.src.logger.msgs import (
    errors
)

# Handlers
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
def serve(
    log_level: int = typer.Option(0, "--log-level", help="The log level, ranges from 0 to 3. [INFO: 0, DEBUG: 1, ERROR: 2, CRITICAL: 3]")
):
    """ Serve PufferBlow's API """
    if log_level > 3:
        console.log("[bold red] [ ? ] [reset]The log level is set too high (max is 3).")
        sys.exit(1)
    
    if config_handler.check_config() or config_handler.is_default_config():
        # console.log("[bold red] [ ? ] [reset]Please finish the [bold green]setup process[reset] in the web interface before running the api.");
        # sys.exit(1)
        pass
    
    log_level = constants.log_level_map[log_level]

    INTERCEPT_HANDLER = InterceptHandler()
    logging.basicConfig(handlers=[INTERCEPT_HANDLER], level=log_level)
    logging.root.handlers = [INTERCEPT_HANDLER]
    logging.root.setLevel(log_level)

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

    logger.configure(handlers=[{"sink": sys.stdout}])
    logger.add(pufferblow_api_config.LOGS_PATH, rotation="10 MB")

    StubbedGunicornLogger.log_level = log_level

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

def run() -> None: constants.banner(); cli()
