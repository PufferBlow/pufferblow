import sys
import typer

from rich import print
from loguru import logger
from rich.prompt import Prompt, Confirm
from rich.console import Console
from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns
from rich.layout import Layout
from rich.live import Live
import time

from pufferblow import constants
from pufferblow.api.api import api

from pufferblow.api.logger.logger import (
    InterceptHandler,
    logging,
    StandaloneApplication,
    StubbedGunicornLogger,
    WORKERS
)

# Base
from pufferblow.api.database.tables.declarative_base import Base

from pufferblow.api_initializer import api_initializer

# Log messages
from pufferblow.api.logger.msgs import (
    errors
)
from pufferblow.api.logger.levels import (
    LOG_LEVEL_MAP
)

# Utils
from pufferblow.api.utils.prompt import ask_prompt

# Config handler
from pufferblow.api.config.config_handler import ConfigHandler

# Models
from pufferblow.api.models.config_model import Config 

# Database
from pufferblow.api.database.database import Database

# Init cli
cli = typer.Typer()

# Init console
console = Console()

# Config is loaded per-command as needed to avoid import-time issues

def display_setup_welcome():
    """Display the modern setup welcome screen"""
    # Clear screen for fresh start
    console.clear()

    # Welcome banner
    welcome_panel = Panel.fit(
        "[bold cyan]Welcome to PufferBlow Setup Wizard[/bold cyan]\n\n"
        "[dim]Host your own secure, open-source chat server[/dim]\n"
        "[dim]Built with care by the PufferBlow team[/dim]",
        title="[bold yellow]PufferBlow Server Setup[/bold yellow]",
        border_style="cyan",
        padding=(1, 2)
    )
    console.print(welcome_panel)
    console.print()

def choose_setup_mode():
    """Interactive setup mode selection"""
    console.print("[bold]Choose your setup workflow:[/bold]")
    console.print()

    modes = [
        {
            "key": "1",
            "prefix": "[+] ",
            "title": "Full Server Setup",
            "description": "Complete installation - database, server config & admin account",
            "time": "~5-10 mins",
            "recommended": True
        },
        {
            "key": "2",
            "prefix": "[>] ",
            "title": "Server Configuration Only",
            "description": "Configure server info when you already have a config file",
            "time": "~2 mins",
            "recommended": False
        },
        {
            "key": "3",
            "prefix": "[~] ",
            "title": "Update Existing Server",
            "description": "Modify server information without database changes",
            "time": "~1 min",
            "recommended": False
        },
        {
            "key": "4",
            "prefix": "[X] ",
            "title": "Cancel Setup",
            "description": "Exit the setup wizard",
            "time": "Immediate",
            "recommended": False
        }
    ]

    for mode in modes:
        rec_marker = " [bold green](Recommended)[/bold green]" if mode["recommended"] else ""
        console.print(f"  [{mode['key']}] {mode['prefix']}[bold]{mode['title']}[/bold]{rec_marker}")
        console.print(f"      {mode['description']}")
        console.print(f"      [dim](Estimated time: {mode['time']})[/dim]")
        console.print()

    # Enhanced selection with validation
    while True:
        choice = Prompt.ask(
            "[bold cyan]Select an option[/bold cyan]",
            choices=["1", "2", "3", "4"],
            default="1"
        )

        return choice

def setup_database() -> tuple:
    """
    Setups the database.

    Args:
        None.

    Returns:
        tuple: The database's connection info.
    """
    database_name = ask_prompt(prompt="PostgreSQL database name", name="database name", default="postgres")
    username = ask_prompt(prompt="PostgreSQL database username", name="database username")
    password = ask_prompt(prompt="PostgreSQL database password", name="database password", password=True)
    host = ask_prompt(prompt="PostgreSQL database host", name="database host", default="localhost")
    port = ask_prompt(prompt="PostgreSQL database port", name="database port", default="5432")

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
        is_update (bool, default: False): Whether to update the row containing the server info instead of creating it.

    Returns:
        None.
    """
    server_name = ask_prompt(prompt="Enter your server's name", name="server's name")
    server_description = ask_prompt(prompt="Enter your server's description", name="server's description")
    server_welcome_message = ask_prompt(prompt="Enter your server's welcome message for new members", name="server's welcome message")
    
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
    # Handle legacy flag-based setup (backwards compatibility)
    if is_setup_server or is_update_server:
        config_handler = ConfigHandler()
        is_config_present = config_handler.check_config()

    # Interactive setup wizard for new users
    config_handler = ConfigHandler()
    is_config_present = config_handler.check_config()

    if not is_setup_server and not is_update_server:
        display_setup_welcome()
        setup_choice = choose_setup_mode()

        if setup_choice == "4":  # Cancel
            console.print("[dim]Setup cancelled. Goodbye!\n[/dim]")
            exit(0)
        elif setup_choice == "2":  # Server Configuration Only
            is_setup_server = True
        elif setup_choice == "3":  # Update Existing Server
            is_update_server = True
        # setup_choice == "1" falls through to full setup (current default behavior)

    # Handle flag-based setup (legacy or interactive selection results)
    if is_setup_server or is_update_server:
        if not is_config_present:
            logger.error("Failed to setup the server, no config file was found to proceed with this operation.")
            exit(1)

        # Load config for server setup
        config_content = config_handler.load_config()
        config = Config(config=config_content)

        # Try to connect using existing config, but allow user to fix it if needed
        database_uri = Database._create_database_uri(
            username=config.USERNAME,
            password=config.DATABASE_PASSWORD,
            host=config.DATABASE_HOST,
            port=config.DATABASE_PORT,
            database_name=config.DATABASE_NAME,
        )

        # Temporarily disable logging during setup for clean visual experience
        logger.remove()
        if not Database.check_database_existense(database_uri):
            console.print("[yellow]Warning:[/yellow] Cannot connect to database with existing configuration.")
            console.print("Please re-enter your database credentials.")

            # Use the setup_database function for a consistent experience and verify connection
            database_uri, database_name, username, password, host, port = setup_database()

            # Update config with new credentials
            config.DATABASE_NAME = database_name
            config.USERNAME = username
            config.DATABASE_PASSWORD = password
            config.DATABASE_HOST = host
            config.DATABASE_PORT = port

            # Save updated config
            config_toml = config.export_toml()
            config_handler.write_config(config=config_toml)

        # Now that database is verified, proceed with server setup
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            # Load objects
            task = progress.add_task("Loading system objects...")
            api_initializer.load_objects(database_uri)

            # Check server status
            if api_initializer.server_manager.check_server_exists() and is_setup_server:
                logger.error("Server info are already set if you want to update them, then please use the flag '--update-server' instead of '--setup-server'")
                exit(1)

            # Setup/update server
            progress.update(task, description="Setting up server information...")
            setup_server(is_update=is_update_server)

        logger.info(f"Server {'created' if not is_update_server else 'updated'} successfully")

        exit(0)

    # Full setup wizard (no flags provided or interactive mode chose full setup)
    if is_config_present:
        is_to_proceed = Confirm.ask("A config file already exists. Do you want to continue?")

        if not is_to_proceed:
            exit(0)

    config = Config()

    # Collect all user input before showing progress bars
    console.print("[dim]-> Gathering setup information...[/dim]")
    database_uri, database_name, username, password, host, port = setup_database()
    console.print("[green][OK] Database connection verified! Setup info collected.[/green]")
    console.print()

    # Update config with verified credentials
    config.DATABASE_NAME = database_name
    config.USERNAME = username
    config.DATABASE_PASSWORD = password
    config.DATABASE_HOST = host
    config.DATABASE_PORT = port

    # Setup server interactively (before progress bars)
    console.print("[dim]-> Configuring server information...[/dim]")
    server_name = ask_prompt(prompt="Enter your server's name", name="server's name")
    server_description = ask_prompt(prompt="Enter your server's description", name="server's description")
    server_welcome_message = ask_prompt(prompt="Enter your server's welcome message for new members", name="server's welcome message")
    console.print("[green][OK] Server information collected![/green]")
    console.print()

    # Setup owner account interactively (before progress bars)
    console.print("[dim]-> Creating owner account...[/dim]")
    owner_username = ask_prompt(prompt="Enter your owner account username", name="owner account username")
    owner_password = ask_prompt(prompt="Enter your owner account password", name="owner account password", password=True)
    console.print("[green][OK] Owner account information collected![/green]")
    console.print()

    # Now start the setup progress with verified prerequisites
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        overall_task = progress.add_task("Setting up PufferBlow...", total=3)

        # Step 1: Load objects (database setup already done)
        progress.update(overall_task, advance=1, description="Initializing system components...")
        api_initializer.load_objects(database_uri)

        # Check server status after loading
        if api_initializer.server_manager.check_server_exists():
            console.print("[bold red]Error:[/bold red] Server already exists. Use --update-server flag if needed.")
            exit(1)

        # Step 2: Initialize system data, create server, and owner account
        progress.update(overall_task, advance=1, description="Initializing system and creating accounts...")

        # Initialize default roles, privileges, and server settings
        api_initializer.database_handler.initialize_default_data()

        # Create server
        api_initializer.server_manager.create_server(
            server_name=str(server_name),
            description=str(server_description),
            server_welcome_message=str(server_welcome_message)
        )

        # Create owner account
        auth_token = api_initializer.user_manager.sign_up(
            username=str(owner_username),
            password=str(owner_password),
            is_admin=True,
            is_owner=True
        ).raw_auth_token

        # Step 3: Save configuration
        progress.update(overall_task, advance=1, description="Saving configuration...")
        config_toml = config.export_toml()
        config_handler.write_config(config=config_toml)

        progress.update(overall_task, completed=3)

    console.print("[green]DONE Setup completed successfully![/green]")

    # Hide any subsequent logs for clean output
    logger.remove()

    # Display auth token in a panel
    auth_panel = Panel.fit(
        f"[bold green]{auth_token}[/bold green]\n\n[bold red]DO NOT SHARE THIS TOKEN![/bold red]",
        title="[bold yellow]Your Server Auth Token[/bold yellow]",
        border_style="blue"
    )
    console.print(auth_panel)

    console.print(f"[green]DONE Configuration saved to '{config_handler.config_file_path}'[/green]")

    # Post-setup guidance panel
    next_steps = Panel.fit(
        "[bold cyan]Ready to launch your server![/bold cyan]\n\n"
        "[bullet] [bold green]Start your server:[/bold green]\n"
        f"   [dim]pufferblow serve[/dim]\n\n"
        "[bullet] [bold green]Access admin panel:[/bold green]\n"
        "   [dim]Open: https://your-server.com/control-panel[/dim]\n\n"
        "[bullet] [bold green]Create your first channel:[/bold green]\n"
        "   [dim]Use your admin account to get started![/dim]\n\n"
        "[dim]Documentation: https://pufferblow.github.io/pufferblow/[/dim]",
        title="[green]Setup Complete![/green]",
        border_style="green",
        padding=(1, 2)
    )
    console.print(next_steps)

@cli.command()
def serve(
    log_level: int = typer.Option(0, "--log-level", help="The log level, ranges from 0 to 3. [INFO: 0, DEBUG: 1, ERROR: 2, CRITICAL: 3]"),
    debug: bool = typer.Option(False, "--debug", help="Enable debug logging"),
    dev: bool = typer.Option(False, "--dev", help="Enable development mode with auto-reload")
):
    """ Serve the API """
    if debug:
        log_level = 1  # Set to debug level when --debug flag is used

    if log_level > 3:
        logger.info("[bold red] [ ? ] [reset]The log level is set too high (max is 3).")
        exit(1)

    # Load config
    config_handler = ConfigHandler()
    if config_handler.check_config():
        config = Config(config=config_handler.load_config())
    else:
        logger.error("Configuration file not found. Please run 'pufferblow setup' first.")
        exit(1)

    # Check if the database exists or not
    database_uri = Database._create_database_uri(
        username=config.USERNAME,
        password=config.DATABASE_PASSWORD,
        host=config.DATABASE_HOST,
        port=config.DATABASE_PORT,
        database_name=config.DATABASE_NAME,
    )

    logger.debug("Checking the database existence...")

    if not Database.check_database_existense(
        database_uri=database_uri
    ):
        logger.error("The specified database does not exist. Please verify the database name and connection details.")
        exit(1)

    # Load shared objects
    logger.debug("Loading objects...")
    api_initializer.load_objects()

    # Setup tables
    logger.debug("Setting up the tables (if necessary)...")
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

    # Check if in development mode (hot reload)
    if dev:
        logger.info("Starting server in development mode with auto-reload...")
        try:
            import uvicorn
            uvicorn.run(
                "pufferblow.api.api:api",
                host=config.API_HOST,
                port=config.API_PORT,
                reload=True,
                log_level=log_level_str.lower(),
                access_log=False,
                server_header=False,
                date_header=False
            )
        except ImportError:
            logger.warning("uvicorn not installed. Falling back to production server without hot reload.")
            dev = False

    if not dev:
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
    cli()
