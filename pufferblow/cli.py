import sys
import typer

from rich import print
from typing import Type
from loguru import logger
from rich.prompt import Prompt, Confirm
from rich.console import Console

from pufferblow import constants
from pufferblow.api import api

from pufferblow.src.logger.logger import (
    InterceptHandler,
    logging,
    StandaloneApplication,
    StubbedGunicornLogger,
    WORKERS
)

# Base
from pufferblow.src.database.tables.declarative_base import Base

from pufferblow.api_initializer import api_initializer

# Log messages
from pufferblow.src.logger.msgs import (
    errors
)

# Utils
from pufferblow.src.utils.prompt import ask_prompt

# Config handler
from pufferblow.src.config.config_handler import ConfigHandler

# Models
from pufferblow.src.models.config_model import Config 

# Database
from pufferblow.src.database.database import Database
from pufferblow.src.database.database_handler import DatabaseHandler

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

config_content = config_handler.load_config()
if len(config_content) == 0:
    config = Config()
else:
    config = Config(
        config=config_handler.load_config()
    )

@cli.command()
def version():
    """ pufferblow's current version """
    print(f"[bold cyan]pufferblow [reset]{constants.VERSION}")

@cli.command()
def setup():
    """ setup pufferblow """
    if config_handler.check_config():
        is_to_proceed = Confirm.ask("A config file already exists. Do you want to continue?")

        if not is_to_proceed:
            sys,exit(0)
    
    config = PufferBlowAPIconfig()
    
    # Supabase
    supabase_url = ask_prompt(prompt="Enter your supabase url", name="supabase url")
    supabase_key = ask_prompt(prompt="Enter your supabase key", name="supabase key")

    config.SUPABASE_URL = supabase_url
    config.SUPABASE_KEY = supabase_key

    # Database related questions
    database_name = Prompt.ask("PostgreSQL database name", default="postgres")
    username = ask_prompt(prompt="PostgreSQl database username", name="username") 
    password = ask_prompt(prompt="PostgreSQL database password", name="password", password=True)
    host = ask_prompt(prompt="PostgreSQL database's host", name="host")
    port = ask_prompt(prompt="PostgreSQL database's port", name="port", default=6543)
    
    logger.info("Attempting to connect to the database.")
    
    database_uri = Database._create_database_uri(
        username=username,
        password=password,
        host=host,
        port=port,
        database_name=database_name
    ) 

    logger.debug(f"Database URI: '{database_uri}'")

    if not Database.check_database_existense(database_uri):
        logger.error(f"The specified database does not exist. Please verify the database name and connection details.")
        sys.exit(1)
    
    config.DATABASE_NAME = database_name
    config.USERNAME = username
    config.DATABASE_PASSWORD = password
    config.DATABASE_HOST = host
    config.DATABASE_PORT = port

    # Creating the server owner's account
    api_initializer.load_objects(database_uri)

    username = ask_prompt(prompt="Enter your owner account username", name="account username")
    password = ask_prompt(prompt="Enter your owner account password", name="account password", password=True)

    user = api_initializer.user_manager.sign_up(
        username=username,
        password=password,
        is_admin=True,
        is_owner=True
    )

    logger.info(f"Your auth-token is '{user.raw_auth_token}'. DO NOT GIVE IT TO ANYONE")
    
    # Save the config
    config_toml = config.export_toml()
    config_handler.write_config(config=config_toml)
    
    logger.info(f"Config saved at '{config_handler.config_file_path}'")

@cli.command()
def serve(
    log_level: int = typer.Option(0, "--log-level", help="The log level, ranges from 0 to 3. [INFO: 0, DEBUG: 1, ERROR: 2, CRITICAL: 3]")
):
    """ Serve the API """
    if log_level > 3:
        logger.info("[bold red] [ ? ] [reset]The log level is set too high (max is 3).")
        sys.exit(1)

    # Check if the database exists or not
    database_uri = Database._create_database_uri(
        username=config.USERNAME,
        password=config.DATABASE_PASSWORD,
        host=config.DATABASE_HOST,
        port=config.DATABASE_PORT,
        database_name=config.DATABASE_NAME,
    )

    if not Database.check_database_existense(
        database_uri=database_uri
    ):
        logger.error("The specified database does not exist. Please verify the database name and connection details.")
        sys.exit(1)

    # Load shared objects
    api_initializer.load_objects()

    # Setup tables
    api_initializer.database_handler.setup_tables(Base)

    log_level_str = constants.log_level_map[log_level]

    INTERCEPT_HANDLER = InterceptHandler()
    logging.basicConfig(handlers=[INTERCEPT_HANDLER], level=log_level_str)
    logging.root.handlers = [INTERCEPT_HANDLER]
    logging.root.setLevel(log_level_str)

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
    logger.add(config.LOGS_PATH, rotation="10 MB")

    StubbedGunicornLogger.log_level = log_level_str

    OPTIONS = {
        "bind": f"{config.API_HOST}:{config.API_PORT}",
        "workers": WORKERS(config.WORKERS),
        "timeout": 86400, # 24 hours
        "keepalive": 86400, # 24 hours
        "accesslog": "-",
        "errorlog": "-",
        "worker_class": "uvicorn.workers.UvicornWorker",
        "logger_class": StubbedGunicornLogger
    }

    StandaloneApplication(api, OPTIONS).run()

def run() -> None:
    constants.banner()

    # Basic checks before starting the cli, this eliminates the need for
    # repetitive checks at the command's function level.
    if config_handler.check_config() or config_handler.is_default_config():
        # console.log("[bold red][ ? ] [reset]Please start the [bold green]setup process[reset] using the [bold green]setup[reset] command.")
        # sys.exit(1)
        pass

    cli()

