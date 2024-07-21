import sys
from typing import Callable
import typer

from rich import print
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
from pufferblow.src.logger.levels import (
    LOG_LEVEL_MAP
)

# Utils
from pufferblow.src.utils.prompt import ask_prompt

# Config handler
from pufferblow.src.config.config_handler import ConfigHandler

# Models
from pufferblow.src.models.config_model import Config 

# Database
from pufferblow.src.database.database import Database

# Init cli
cli = typer.Typer()

# Init console
console = Console()

# Pre-init the config handler and the config model
# TODO: Find a better to do this
config_handler = ConfigHandler()

if not config_handler.check_config():
    logger.error(errors.ERROR_NO_CONFIG_FILE_FOUND(config_handler.config_file_path))
    exit(1)

config_content = config_handler.load_config()
if len(config_content) == 0:
    config = Config()
else:
    config = Config(
        config=config_handler.load_config()
    )

def setup_supabase() -> tuple:
    """
    Setup supabase.

    Args:
        None.

    Returns:
        tuple: Supabase project's info.
    """
    supabase_url = ask_prompt(prompt="Enter your supabase url", name="supabase url")
    supabase_key = ask_prompt(prompt="Enter your supabase key", name="supabase key")

    return (supabase_url, supabase_key)

def setup_database() -> tuple:
    """
    Setups the database.

    Args:
        None.

    Returns:
        tuple: The database's connection info.
    """
    database_name = Prompt.ask("PostgreSQL database name", default="postgres")
    username = ask_prompt(prompt="PostgreSQl database username", name="username") 
    password = ask_prompt(prompt="PostgreSQL database password", name="password", password=True)
    host = ask_prompt(prompt="PostgreSQL database's host", name="host")
    port = ask_prompt(prompt="PostgreSQL database's port", name="port", default=6543)
    
    logger.info("Attempting to connect to the database.")
    
    database_uri = Database._create_database_uri(
        username=str(username),
        password=str(password),
        host=str(host),
        port=int(port),
        database_name=database_name
    ) 

    logger.debug(f"Database URI: '{database_uri}'")

    if not Database.check_database_existense(database_uri):
        logger.error(f"The specified database does not exist. Please verify the database name and connection details.")
        exit(1)

    return (database_uri, database_name, username, password, host, port)

def setup_owner_account() -> str:
    """
    Setup the owner's account.

    Args:
        None.

    Returns:
        str: The owner account's auth_token.
    """
    username = ask_prompt(prompt="Enter your owner account username", name="account username")
    password = ask_prompt(prompt="Enter your owner account password", name="account password", password=True)

    user = api_initializer.user_manager.sign_up(
        username=str(username),
        password=str(password),
        is_admin=True,
        is_owner=True
    )

    return user.raw_auth_token

def setup_server(is_update: bool | None = False) -> None:
    """
    Setup the server info.

    Args:
        is_update (bool, default: False): Wether to update the row containing the server info instead of creating it.

    Returns:
        None.
    """
    server_name = ask_prompt(prompt="Enter your server's name", name="server's name")
    server_description = ask_prompt(prompt="Enter your server's description", name="server's description")
    server_welcome_message = ask_prompt(prompt="Enter your server's welcome message for new members", name="sever's welcome message")
    
    if is_update:
        func = api_initializer.server_manager.update_server
    else:
        func = api_initializer.server_manager.create_server

    func(
        server_name=str(server_name),
        description=str(server_description),
        server_welcome_message=str(server_welcome_message)
    )

@cli.command()
def version():
    """ pufferblow's current version """
    print(f"[bold cyan]pufferblow [reset]{constants.VERSION}")

@cli.command()
def setup(
    is_setup_server: bool = typer.Option(False, "--setup-server", help="Only setup the server's info."),
    is_update_server: bool = typer.Option(False, "--update-server", help="Update the server's info like name, description and welcome message.")
):
    """ setup pufferblow """
    is_config_present = config_handler.check_config()

    if is_setup_server or is_update_server:
        if not is_config_present:
            logger.error("Faild to setup the server, no config file was found to proceed with this operation.")
            exit(1) 

        api_initializer.load_objects()
        
        if api_initializer.server_manager.check_server_exists() and is_setup_server:
            logger.error("Server info are already set if you want to update them, then please use the flag '--update-server' instead of '--setup-server'")
            exit(1)

        setup_server(is_update=is_update_server)

        logger.info(f"Server {'created' if not is_update_server else 'updated'} successfuly")

        exit(0)
    
    if is_config_present:
        is_to_proceed = Confirm.ask("A config file already exists. Do you want to continue?")

        if not is_to_proceed:
            exit(0)
    
    config = Config()
    
    # Supabase 
    supabase_url, supabase_key = setup_supabase()

    config.SUPABASE_URL = supabase_url
    config.SUPABASE_KEY = supabase_key

    # Database related questions
    database_uri, database_name, username, password, host, port = setup_database() 
    
    config.DATABASE_NAME = database_name
    config.USERNAME = username
    config.DATABASE_PASSWORD = password
    config.DATABASE_HOST = host
    config.DATABASE_PORT = port
    
    # Load the objects
    api_initializer.load_objects(database_uri)
    
    # Create the server
    setup_server()

    # Creating the server owner's account
    auth_token = setup_owner_account() 

    logger.info(f"Your auth-token is '{auth_token}'. DO NOT GIVE IT TO ANYONE")
    
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
        exit(1)

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
        exit(1)

    # Load shared objects
    api_initializer.load_objects()

    # Setup tables
    api_initializer.database_handler.setup_tables(Base)

    log_level_str = LOG_LEVEL_MAP[log_level]

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
        # exit(1)
        pass

    cli()

