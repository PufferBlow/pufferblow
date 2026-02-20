import sys
from pathlib import Path

import typer
from loguru import logger
from rich import print
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    TextColumn,
)
from rich.prompt import Confirm, Prompt

from pufferblow import constants
from pufferblow.api.api import api

# Config handler
from pufferblow.api.config.config_handler import ConfigHandler

# Database
from pufferblow.api.database.database import Database

# Base
from pufferblow.api.database.tables.declarative_base import Base
from pufferblow.api.logger.levels import LOG_LEVEL_MAP
from pufferblow.api.logger.logger import (
    WORKERS,
    InterceptHandler,
    StandaloneApplication,
    StubbedGunicornLogger,
    logging,
)

# Log messages
# Models
from pufferblow.api.models.config_model import Config

# Utils
from pufferblow.api.utils.prompt import ask_prompt
from pufferblow.api_initializer import api_initializer

# Init cli
cli = typer.Typer()

# Init storage subcommand
storage_cli = typer.Typer()
cli.add_typer(
    storage_cli, name="storage", help="Manage storage backends and configuration"
)

# Init console
console = Console()

INFORMATIVE_LOG_FORMAT = (
    "{time:YYYY-MM-DD HH:mm:ss.SSS} | {level:<8} | "
    "request_id={extra[request_id]} | method={extra[method]} | path={extra[path]} | "
    "status={extra[status_code]} | duration_ms={extra[duration_ms]} | client_ip={extra[client_ip]} | "
    "{name}:{function}:{line} | {message}"
)


def _enrich_log_record(record: dict) -> None:
    """
    Ensure commonly used structured fields always exist in log records.
    """
    extra = record["extra"]
    extra.setdefault("request_id", "-")
    extra.setdefault("method", "-")
    extra.setdefault("path", "-")
    extra.setdefault("status_code", "-")
    extra.setdefault("duration_ms", "-")
    extra.setdefault("client_ip", "-")


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
        padding=(1, 2),
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
            "recommended": True,
        },
        {
            "key": "2",
            "prefix": "[>] ",
            "title": "Server Configuration Only",
            "description": "Configure server info when you already have a config file",
            "time": "~2 mins",
            "recommended": False,
        },
        {
            "key": "3",
            "prefix": "[~] ",
            "title": "Update Existing Server",
            "description": "Modify server information without database changes",
            "time": "~1 min",
            "recommended": False,
        },
        {
            "key": "4",
            "prefix": "[X] ",
            "title": "Cancel Setup",
            "description": "Exit the setup wizard",
            "time": "Immediate",
            "recommended": False,
        },
    ]

    for mode in modes:
        rec_marker = (
            " [bold green](Recommended)[/bold green]" if mode["recommended"] else ""
        )
        console.print(
            f"  [{mode['key']}] {mode['prefix']}[bold]{mode['title']}[/bold]{rec_marker}"
        )
        console.print(f"      {mode['description']}")
        console.print(f"      [dim](Estimated time: {mode['time']})[/dim]")
        console.print()

    # Enhanced selection with validation
    while True:
        choice = Prompt.ask(
            "[bold cyan]Select an option[/bold cyan]",
            choices=["1", "2", "3", "4"],
            default="1",
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
    database_name = ask_prompt(
        prompt="PostgreSQL database name", name="database name", default="postgres"
    )
    username = ask_prompt(
        prompt="PostgreSQL database username", name="database username"
    )
    password = ask_prompt(
        prompt="PostgreSQL database password", name="database password", password=True
    )
    host = ask_prompt(
        prompt="PostgreSQL database host", name="database host", default="localhost"
    )
    port = ask_prompt(
        prompt="PostgreSQL database port", name="database port", default="5432"
    )

    logger.info("Attempting to connect to the database.")

    database_uri = Database._create_database_uri(
        username=str(username),
        password=str(password),
        host=str(host),
        port=int(port),
        database_name=database_name,
    )

    logger.debug(f"Database URI: '{database_uri}'")

    if not Database.check_database_existense(database_uri):
        logger.error(
            "The specified database does not exist. Please verify the database name and connection details."
        )
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
    username = ask_prompt(
        prompt="Enter your owner account username", name="account username"
    )
    password = ask_prompt(
        prompt="Enter your owner account password",
        name="account password",
        password=True,
    )

    user = api_initializer.user_manager.sign_up(
        username=str(username), password=str(password), is_admin=True, is_owner=True
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
    server_description = ask_prompt(
        prompt="Enter your server's description", name="server's description"
    )
    server_welcome_message = ask_prompt(
        prompt="Enter your server's welcome message for new members",
        name="server's welcome message",
    )

    if is_update:
        func = api_initializer.server_manager.update_server
    else:
        func = api_initializer.server_manager.create_server

    func(
        server_name=str(server_name),
        description=str(server_description),
        server_welcome_message=str(server_welcome_message),
    )


def _launch_textual_setup(has_existing_config: bool):
    """
    Launch the Textual setup wizard.

    Returns:
        tuple[str, object | None]:
            - ("ok", payload) when setup input is collected.
            - ("cancelled", None) when user cancels.
            - ("missing_dependency", None) when Textual is not installed.
    """
    try:
        from pufferblow.cli.textual_setup import SetupWizardApp
    except ImportError:
        return ("missing_dependency", None)

    app = SetupWizardApp(has_existing_config=has_existing_config)
    app.run()
    if app.result is None:
        return ("cancelled", None)
    return ("ok", app.result)


def _apply_server_configuration(
    *,
    is_update: bool,
    server_name: str,
    server_description: str,
    server_welcome_message: str,
) -> None:
    if is_update:
        api_initializer.server_manager.update_server(
            server_name=server_name,
            description=server_description,
            server_welcome_message=server_welcome_message,
        )
        return

    api_initializer.server_manager.create_server(
        server_name=server_name,
        description=server_description,
        server_welcome_message=server_welcome_message,
    )


def _run_textual_setup_payload(payload, config_handler: ConfigHandler) -> None:
    """
    Execute setup workflow from Textual payload.
    """
    if payload.mode in ("server_only", "server_update"):
        if not config_handler.check_config():
            logger.error(
                "No config file found. Run full setup first to initialize the server."
            )
            raise typer.Exit(code=1)

        config = Config(config=config_handler.load_config())
        database_uri = Database._create_database_uri(
            username=config.USERNAME,
            password=config.DATABASE_PASSWORD,
            host=config.DATABASE_HOST,
            port=config.DATABASE_PORT,
            database_name=config.DATABASE_NAME,
        )

        if not Database.check_database_existense(database_uri):
            logger.error(
                "Configured database is unreachable. Fix config and rerun setup."
            )
            raise typer.Exit(code=1)

        api_initializer.load_objects(database_uri)

        if (
            payload.mode == "server_only"
            and api_initializer.server_manager.check_server_exists()
        ):
            logger.error(
                "Server already exists. Use update mode to modify server information."
            )
            raise typer.Exit(code=1)

        _apply_server_configuration(
            is_update=payload.mode == "server_update",
            server_name=payload.server_name,
            server_description=payload.server_description,
            server_welcome_message=payload.server_welcome_message,
        )
        logger.info("Server setup completed via Textual wizard.")
        raise typer.Exit(code=0)

    config = Config()
    database_uri = Database._create_database_uri(
        username=payload.database_username,
        password=payload.database_password,
        host=payload.database_host,
        port=int(payload.database_port),
        database_name=payload.database_name,
    )

    if not Database.check_database_existense(database_uri):
        logger.error(
            "The specified database does not exist. Verify credentials and rerun setup."
        )
        raise typer.Exit(code=1)

    config.DATABASE_NAME = payload.database_name
    config.USERNAME = payload.database_username
    config.DATABASE_PASSWORD = payload.database_password
    config.DATABASE_HOST = payload.database_host
    config.DATABASE_PORT = payload.database_port

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        overall_task = progress.add_task("Setting up PufferBlow...", total=3)
        progress.update(
            overall_task, advance=1, description="Initializing system components..."
        )
        api_initializer.load_objects(database_uri)

        if api_initializer.server_manager.check_server_exists():
            logger.error(
                "Server already exists. Use update mode instead of full setup."
            )
            raise typer.Exit(code=1)

        progress.update(
            overall_task,
            advance=1,
            description="Creating server and owner account...",
        )
        api_initializer.database_handler.initialize_default_data()
        _apply_server_configuration(
            is_update=False,
            server_name=payload.server_name,
            server_description=payload.server_description,
            server_welcome_message=payload.server_welcome_message,
        )
        auth_token = api_initializer.user_manager.sign_up(
            username=payload.owner_username,
            password=payload.owner_password,
            is_admin=True,
            is_owner=True,
        ).raw_auth_token

        progress.update(overall_task, advance=1, description="Saving configuration...")
        config_handler.write_config(config=config.export_toml())
        progress.update(overall_task, completed=3)

    console.print("[green]DONE Setup completed successfully![/green]")
    auth_panel = Panel.fit(
        f"[bold green]{auth_token}[/bold green]\n\n[bold red]DO NOT SHARE THIS TOKEN![/bold red]",
        title="[bold yellow]Your Server Auth Token[/bold yellow]",
        border_style="blue",
    )
    console.print(auth_panel)
    console.print(
        f"[green]DONE Configuration saved to '{config_handler.config_file_path}'[/green]"
    )
    raise typer.Exit(code=0)


@cli.command()
def version():
    """pufferblow's current version"""
    print(f"[bold cyan]pufferblow [reset]{constants.VERSION}")


@cli.command()
def setup(
    is_setup_server: bool = typer.Option(
        False, "--setup-server", help="Only setup the server's info."
    ),
    is_update_server: bool = typer.Option(
        False,
        "--update-server",
        help="Update the server's info like name, description and welcome message.",
    ),
):
    """setup pufferblow"""
    config_handler = ConfigHandler()
    is_config_present = config_handler.check_config()

    if not is_setup_server and not is_update_server:
        setup_state, payload = _launch_textual_setup(
            has_existing_config=is_config_present
        )
        if setup_state == "ok":
            _run_textual_setup_payload(payload, config_handler=config_handler)
            return
        if setup_state == "cancelled":
            console.print("[dim]Setup cancelled. Goodbye!\n[/dim]")
            raise typer.Exit(code=0)

        logger.warning(
            "Textual is not installed. Falling back to legacy prompt-based setup."
        )
        display_setup_welcome()
        setup_choice = choose_setup_mode()
        if setup_choice == "4":
            console.print("[dim]Setup cancelled. Goodbye!\n[/dim]")
            raise typer.Exit(code=0)
        if setup_choice == "2":
            is_setup_server = True
        elif setup_choice == "3":
            is_update_server = True

    # Handle flag-based setup (legacy or interactive selection results)
    if is_setup_server or is_update_server:
        if not is_config_present:
            logger.error(
                "Failed to setup the server, no config file was found to proceed with this operation."
            )
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
            console.print(
                "[yellow]Warning:[/yellow] Cannot connect to database with existing configuration."
            )
            console.print("Please re-enter your database credentials.")

            # Use the setup_database function for a consistent experience and verify connection
            database_uri, database_name, username, password, host, port = (
                setup_database()
            )

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
                logger.error(
                    "Server info are already set if you want to update them, then please use the flag '--update-server' instead of '--setup-server'"
                )
                exit(1)

            # Setup/update server
            progress.update(task, description="Setting up server information...")
            setup_server(is_update=is_update_server)

        logger.info(
            f"Server {'created' if not is_update_server else 'updated'} successfully"
        )

        exit(0)

    # Full setup wizard (no flags provided or interactive mode chose full setup)
    if is_config_present:
        is_to_proceed = Confirm.ask(
            "A config file already exists. Do you want to continue?"
        )

        if not is_to_proceed:
            exit(0)

    config = Config()

    # Collect all user input before showing progress bars
    console.print("[dim]-> Gathering setup information...[/dim]")
    database_uri, database_name, username, password, host, port = setup_database()
    console.print(
        "[green][OK] Database connection verified! Setup info collected.[/green]"
    )
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
    server_description = ask_prompt(
        prompt="Enter your server's description", name="server's description"
    )
    server_welcome_message = ask_prompt(
        prompt="Enter your server's welcome message for new members",
        name="server's welcome message",
    )
    console.print("[green][OK] Server information collected![/green]")
    console.print()

    # Setup owner account interactively (before progress bars)
    console.print("[dim]-> Creating owner account...[/dim]")
    owner_username = ask_prompt(
        prompt="Enter your owner account username", name="owner account username"
    )
    owner_password = ask_prompt(
        prompt="Enter your owner account password",
        name="owner account password",
        password=True,
    )
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
        progress.update(
            overall_task, advance=1, description="Initializing system components..."
        )
        api_initializer.load_objects(database_uri)

        # Check server status after loading
        if api_initializer.server_manager.check_server_exists():
            console.print(
                "[bold red]Error:[/bold red] Server already exists. Use --update-server flag if needed."
            )
            exit(1)

        # Step 2: Initialize system data, create server, and owner account
        progress.update(
            overall_task,
            advance=1,
            description="Initializing system and creating accounts...",
        )

        # Initialize default roles, privileges, and server settings
        api_initializer.database_handler.initialize_default_data()

        # Create server
        api_initializer.server_manager.create_server(
            server_name=str(server_name),
            description=str(server_description),
            server_welcome_message=str(server_welcome_message),
        )

        # Create owner account
        auth_token = api_initializer.user_manager.sign_up(
            username=str(owner_username),
            password=str(owner_password),
            is_admin=True,
            is_owner=True,
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
        border_style="blue",
    )
    console.print(auth_panel)

    console.print(
        f"[green]DONE Configuration saved to '{config_handler.config_file_path}'[/green]"
    )

    # Post-setup guidance panel
    next_steps = Panel.fit(
        "[bold cyan]Ready to launch your server![/bold cyan]\n\n"
        "[bullet] [bold green]Start your server:[/bold green]\n"
        "   [dim]pufferblow serve[/dim]\n\n"
        "[bullet] [bold green]Access admin panel:[/bold green]\n"
        "   [dim]Open: https://your-server.com/control-panel[/dim]\n\n"
        "[bullet] [bold green]Create your first channel:[/bold green]\n"
        "   [dim]Use your admin account to get started![/dim]\n\n"
        "[dim]Documentation: https://pufferblow.github.io/pufferblow/[/dim]",
        title="[green]Setup Complete![/green]",
        border_style="green",
        padding=(1, 2),
    )
    console.print(next_steps)


@cli.command()
def serve(
    log_level: int = typer.Option(
        0,
        "--log-level",
        help="The log level, ranges from 0 to 3. [INFO: 0, DEBUG: 1, ERROR: 2, CRITICAL: 3]",
    ),
    debug: bool = typer.Option(False, "--debug", help="Enable debug logging"),
    dev: bool = typer.Option(
        False, "--dev", help="Enable development mode with auto-reload"
    ),
):
    """Serve the API"""
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
        logger.error(
            "Configuration file not found. Please run 'pufferblow setup' first."
        )
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

    if not Database.check_database_existense(database_uri=database_uri):
        logger.error(
            "The specified database does not exist. Please verify the database name and connection details."
        )
        exit(1)

    # Load shared objects
    logger.debug("Loading objects...")
    api_initializer.load_objects()

    # Setup tables
    logger.debug("Setting up the tables (if necessary)...")
    api_initializer.database_handler.setup_tables(Base)

    log_level_str = LOG_LEVEL_MAP[log_level]
    logger.configure(patcher=_enrich_log_record)

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

    # Always configure loguru to write to the config-defined log file, regardless of development/production mode
    logger.add(
        config.LOGS_PATH,
        rotation="10 MB",
        level=log_level_str,
        format=INFORMATIVE_LOG_FORMAT,
    )

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
                date_header=False,
            )
        except ImportError:
            logger.warning(
                "uvicorn not installed. Falling back to production server without hot reload."
            )
            dev = False

    if not dev:
        logger.configure(
            patcher=_enrich_log_record,
            handlers=[
                {
                    "sink": sys.stdout,
                    "level": log_level_str,
                    "format": INFORMATIVE_LOG_FORMAT,
                }
            ],
        )

        StubbedGunicornLogger.log_level = log_level_str

        OPTIONS = {
            "bind": f"{config.API_HOST}:{config.API_PORT}",
            "workers": WORKERS(config.WORKERS),
            "timeout": 86400,  # 24 hours
            "keepalive": 86400,  # 24 hours
            "accesslog": "-",
            "errorlog": "-",
            "worker_class": "uvicorn.workers.UvicornWorker",
            "logger_class": StubbedGunicornLogger,
        }

        StandaloneApplication(api, OPTIONS).run()


def display_storage_welcome():
    """Display the modern storage setup welcome screen"""
    # Clear screen for fresh start
    console.clear()

    # Welcome banner
    welcome_panel = Panel.fit(
        "[bold cyan]PufferBlow Storage Setup Wizard[/bold cyan]\n\n"
        "[dim]Configure your file storage backend[/dim]\n"
        "[dim]Choose between local storage or cloud providers[/dim]",
        title="[bold yellow]Storage Configuration[/bold yellow]",
        border_style="cyan",
        padding=(1, 2),
    )
    console.print(welcome_panel)
    console.print()


def choose_storage_provider():
    """Interactive storage provider selection"""
    console.print("[bold]Choose your storage backend:[/bold]")
    console.print()

    providers = [
        {
            "key": "1",
            "prefix": "[💾] ",
            "title": "Local Storage",
            "description": "Store files locally on your server with space allocation limits",
            "features": ["10GB limit", "Fast access", "No external costs"],
            "recommended": True,
        },
        {
            "key": "2",
            "prefix": "[☁️]  ",
            "title": "AWS S3",
            "description": "Store files in Amazon S3 buckets with global CDN",
            "features": ["Scalable", "Durable", "Pay per use"],
            "recommended": False,
        },
        {
            "key": "3",
            "prefix": "[🔧] ",
            "title": "S3 Compatible",
            "description": "Use any S3-compatible service (MinIO, DigitalOcean, etc.)",
            "features": ["Flexible", "Self-hosted options", "Cost effective"],
            "recommended": False,
        },
        {
            "key": "4",
            "prefix": "[❌] ",
            "title": "Cancel Setup",
            "description": "Exit the storage setup wizard",
            "features": [],
            "recommended": False,
        },
    ]

    for provider in providers:
        rec_marker = (
            " [bold green](Recommended)[/bold green]" if provider["recommended"] else ""
        )
        console.print(
            f"  [{provider['key']}] {provider['prefix']}[bold]{provider['title']}[/bold]{rec_marker}"
        )
        console.print(f"      {provider['description']}")
        if provider["features"]:
            features_str = ", ".join(f"[dim]{f}[/dim]" for f in provider["features"])
            console.print(f"      [dim]Features: {features_str}[/dim]")
        console.print()

    # Enhanced selection with validation
    while True:
        choice = Prompt.ask(
            "[bold cyan]Select a storage provider[/bold cyan]",
            choices=["1", "2", "3", "4"],
            default="1",
        )

        return choice


def setup_local_storage():
    """Setup local storage configuration"""
    console.print("[bold]Local Storage Configuration[/bold]")
    console.print()

    # Get storage path
    default_path = "./storage"  # Relative to project root
    storage_path = Prompt.ask(
        "[bold cyan]Storage directory path[/bold cyan]", default=default_path
    )

    # Convert to absolute path
    if not storage_path.startswith("/"):
        # Make it relative to current working directory
        storage_path = str(Path.cwd() / storage_path)

    # Validate path
    storage_path_obj = Path(storage_path)
    if storage_path_obj.exists() and not storage_path_obj.is_dir():
        console.print("[bold red]Error:[/bold red] Path exists but is not a directory!")
        return None

    # Get allocation limit
    allocation_gb = Prompt.ask(
        "[bold cyan]Storage allocation limit (GB)[/bold cyan]", default="10"
    )

    try:
        allocation_gb = float(allocation_gb)
        if allocation_gb <= 0:
            raise ValueError("Must be positive")
    except ValueError:
        console.print("[bold red]Error:[/bold red] Invalid allocation limit!")
        return None

    # Check available disk space
    try:
        import shutil

        total, used, free = shutil.disk_usage(storage_path_obj.parent)
        free_gb = free / (1024**3)

        if free_gb < allocation_gb:
            console.print(
                f"[yellow]Warning:[/yellow] Only {free_gb:.1f}GB free space available!"
            )
            if not Confirm.ask("Continue anyway?", default=False):
                return None
    except Exception:
        console.print("[yellow]Warning:[/yellow] Could not check available disk space")

    return {
        "provider": "local",
        "storage_path": storage_path,
        "allocated_space_gb": allocation_gb,
        "base_url": "/api/v1/storage",  # Will be configured by server
    }


def setup_s3_storage(is_aws=True):
    """Setup S3 storage configuration"""
    provider_name = "AWS S3" if is_aws else "S3 Compatible"

    console.print(f"[bold]{provider_name} Configuration[/bold]")
    console.print()

    # Bucket name
    bucket_name = Prompt.ask("[bold cyan]Bucket name[/bold cyan]")

    # Region
    default_region = "us-east-1" if is_aws else ""
    region = Prompt.ask("[bold cyan]Region[/bold cyan]", default=default_region)

    # Access Key
    access_key = Prompt.ask("[bold cyan]Access Key ID[/bold cyan]")

    # Secret Key
    secret_key = Prompt.ask("[bold cyan]Secret Access Key[/bold cyan]", password=True)

    # Endpoint URL (for non-AWS S3)
    endpoint_url = None
    if not is_aws:
        endpoint_url = Prompt.ask(
            "[bold cyan]Endpoint URL[/bold cyan]", default="https://s3.amazonaws.com"
        )

    return {
        "provider": "s3",
        "bucket_name": bucket_name,
        "region": region,
        "access_key": access_key,
        "secret_key": secret_key,
        "endpoint_url": endpoint_url,
        "base_url": (
            f"https://{bucket_name}.s3.{region}.amazonaws.com"
            if is_aws
            else endpoint_url
        ),
    }


def test_storage_config(config):
    """Test the storage configuration"""
    console.print("[bold]Testing Storage Configuration[/bold]")
    console.print()

    try:
        from pufferblow.api.storage.local_storage import LocalStorageBackend
        from pufferblow.api.storage.s3_storage import S3StorageBackend

        # Create backend instance
        if config["provider"] == "local":
            backend = LocalStorageBackend(config)
        elif config["provider"] == "s3":
            backend = S3StorageBackend(config)
        else:
            raise ValueError(f"Unsupported provider: {config['provider']}")

        # Test basic operations
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            # Test 1: Basic connectivity
            task = progress.add_task("Testing connectivity...")
            # For local storage, check if we can create directory
            # For S3, check if we can list objects (will fail gracefully if no permissions)
            try:
                if config["provider"] == "local":
                    Path(config["storage_path"]).mkdir(parents=True, exist_ok=True)
                else:
                    # Try to check if bucket exists (this might fail with permissions)
                    import boto3

                    s3_client = boto3.client(
                        "s3",
                        aws_access_key_id=config["access_key"],
                        aws_secret_access_key=config["secret_key"],
                        region_name=config["region"],
                        endpoint_url=config.get("endpoint_url"),
                    )
                    s3_client.head_bucket(Bucket=config["bucket_name"])
                progress.update(
                    task, description="[green]✓ Connectivity test passed[/green]"
                )
            except Exception as e:
                progress.update(
                    task, description=f"[red]✗ Connectivity test failed: {str(e)}[/red]"
                )
                return False

            # Test 2: Write permissions
            progress.update(task, advance=1, description="Testing write permissions...")
            test_file = "test_config_file.txt"
            test_content = b"Storage configuration test file"

            try:
                success = backend.upload_file(test_content, test_file)
                if not success:
                    raise Exception("Upload returned False")
                progress.update(task, description="[green]✓ Write test passed[/green]")
            except Exception as e:
                progress.update(
                    task, description=f"[red]✗ Write test failed: {str(e)}[/red]"
                )
                return False

            # Test 3: Read permissions
            progress.update(task, advance=1, description="Testing read permissions...")
            try:
                read_content = backend.download_file(test_file)
                if read_content != test_content:
                    raise Exception("Content mismatch")
                progress.update(task, description="[green]✓ Read test passed[/green]")
            except Exception as e:
                progress.update(
                    task, description=f"[red]✗ Read test failed: {str(e)}[/red]"
                )
                return False

            # Test 4: Delete permissions
            progress.update(
                task, advance=1, description="Testing delete permissions..."
            )
            try:
                success = backend.delete_file(test_file)
                if not success:
                    raise Exception("Delete returned False")
                progress.update(task, description="[green]✓ Delete test passed[/green]")
            except Exception as e:
                progress.update(
                    task, description=f"[red]✗ Delete test failed: {str(e)}[/red]"
                )
                return False

        console.print("[green]✓ All storage tests passed![/green]")
        return True

    except Exception as e:
        console.print(f"[red]✗ Storage configuration test failed: {str(e)}[/red]")
        return False


def save_storage_config(storage_config):
    """Save storage configuration to config file"""
    try:
        config_handler = ConfigHandler()

        # Load existing config or create new one
        if config_handler.check_config():
            config_content = config_handler.load_config()
            config = Config(config=config_content)
        else:
            config = Config()

        # Update storage settings
        config.STORAGE_PROVIDER = storage_config["provider"]
        config.STORAGE_PATH = storage_config.get("storage_path", "")
        config.STORAGE_BASE_URL = storage_config.get("base_url", "")
        config.STORAGE_ALLOCATED_GB = storage_config.get("allocated_space_gb", 10)

        # S3 specific settings
        if storage_config["provider"] == "s3":
            config.S3_BUCKET_NAME = storage_config["bucket_name"]
            config.S3_REGION = storage_config["region"]
            config.S3_ACCESS_KEY = storage_config["access_key"]
            config.S3_SECRET_KEY = storage_config["secret_key"]
            config.S3_ENDPOINT_URL = storage_config.get("endpoint_url", "")

        # Save configuration
        config_toml = config.export_toml()
        config_handler.write_config(config=config_toml)

        return True

    except Exception as e:
        console.print(f"[red]Error saving configuration: {str(e)}[/red]")
        return False


@storage_cli.command("setup")
def storage_setup():
    """Interactive storage backend setup wizard"""
    display_storage_welcome()

    # Choose provider
    provider_choice = choose_storage_provider()

    if provider_choice == "4":  # Cancel
        console.print("[dim]Storage setup cancelled. Goodbye!\n[/dim]")
        return

    # Configure based on choice
    storage_config = None

    if provider_choice == "1":  # Local
        storage_config = setup_local_storage()
    elif provider_choice == "2":  # AWS S3
        storage_config = setup_s3_storage(is_aws=True)
    elif provider_choice == "3":  # S3 Compatible
        storage_config = setup_s3_storage(is_aws=False)

    if not storage_config:
        console.print("[bold red]Configuration cancelled or failed![/bold red]")
        return

    console.print()
    console.print("[bold]Configuration Summary:[/bold]")
    for key, value in storage_config.items():
        if "secret" in key.lower() or "key" in key.lower():
            console.print(f"  {key}: [dim]***hidden***[/dim]")
        else:
            console.print(f"  {key}: {value}")
    console.print()

    # Test configuration
    if not Confirm.ask("Test the storage configuration?", default=True):
        console.print("[yellow]Skipping configuration test...[/yellow]")
        test_passed = True
    else:
        test_passed = test_storage_config(storage_config)

    if not test_passed:
        if not Confirm.ask("Configuration test failed. Save anyway?", default=False):
            console.print("[dim]Configuration not saved.[/dim]")
            return

    # Save configuration
    console.print()
    console.print("[bold]Saving configuration...[/bold]")

    if save_storage_config(storage_config):
        console.print("[green]✓ Storage configuration saved successfully![/green]")

        # Success panel
        success_panel = Panel.fit(
            "[bold cyan]Storage backend configured![/bold cyan]\n\n"
            f"[bold green]Provider:[/bold green] {storage_config['provider'].upper()}\n"
            f"[bold green]Status:[/bold green] Ready to use\n\n"
            "[dim]Your server will now use this storage backend for file uploads.[/dim]",
            title="[green]Setup Complete![/green]",
            border_style="green",
            padding=(1, 2),
        )
        console.print(success_panel)

        # Migration hint
        if Confirm.ask(
            "Would you like to migrate existing files to this new storage?",
            default=False,
        ):
            console.print()
            console.print("[bold]To migrate existing files, run:[/bold]")
            console.print(
                "[dim]pufferblow storage migrate --source-provider local --target-provider s3[/dim]"
            )
    else:
        console.print("[bold red]Failed to save configuration![/bold red]")


@storage_cli.command("test")
def storage_test():
    """Test current storage configuration"""
    try:
        config_handler = ConfigHandler()
        if not config_handler.check_config():
            console.print(
                "[bold red]No configuration file found. Run 'pufferblow storage setup' first.[/bold red]"
            )
            return

        config_content = config_handler.load_config()
        config = Config(config=config_content)

        # Build storage config from current settings
        storage_config = {
            "provider": config.STORAGE_PROVIDER,
            "storage_path": config.STORAGE_PATH,
            "base_url": config.STORAGE_BASE_URL,
            "allocated_space_gb": config.STORAGE_ALLOCATED_GB,
            "bucket_name": config.S3_BUCKET_NAME,
            "region": config.S3_REGION,
            "access_key": config.S3_ACCESS_KEY,
            "secret_key": config.S3_SECRET_KEY,
            "endpoint_url": config.S3_ENDPOINT_URL,
        }

        console.print(
            f"[bold]Testing {storage_config['provider'].upper()} storage configuration...[/bold]"
        )
        console.print()

        if test_storage_config(storage_config):
            console.print(
                "[green]✓ Storage configuration is working correctly![/green]"
            )
        else:
            console.print("[bold red]✗ Storage configuration has issues![/bold red]")
            console.print("[dim]Run 'pufferblow storage setup' to reconfigure.[/dim]")

    except Exception as e:
        console.print(f"[bold red]Error testing storage: {str(e)}[/bold red]")


@storage_cli.command("migrate")
def storage_migrate(
    source_provider: str = typer.Option(
        ..., "--source-provider", help="Source storage provider"
    ),
    target_provider: str = typer.Option(
        ..., "--target-provider", help="Target storage provider"
    ),
    batch_size: int = typer.Option(
        10, "--batch-size", help="Number of files to migrate per batch"
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Analyze migration without executing"
    ),
):
    """Migrate files between storage backends"""
    try:
        config_handler = ConfigHandler()
        if not config_handler.check_config():
            console.print(
                "[bold red]No configuration file found. Run 'pufferblow setup' first.[/bold red]"
            )
            return

        config_content = config_handler.load_config()
        config = Config(config=config_content)

        # Initialize API to get database access
        api_initializer.load_objects()

        # Import migration script
        from scripts.migrate_storage import StorageMigrator

        # Create source config (from current config)
        source_config = {
            "provider": source_provider,
            "storage_path": config.STORAGE_PATH,
            "base_url": config.STORAGE_BASE_URL,
            "bucket_name": config.S3_BUCKET_NAME,
            "region": config.S3_REGION,
            "access_key": config.S3_ACCESS_KEY,
            "secret_key": config.S3_SECRET_KEY,
            "endpoint_url": config.S3_ENDPOINT_URL,
        }

        # Create target config (from current config, but override provider)
        target_config = source_config.copy()
        target_config["provider"] = target_provider

        console.print(
            f"[bold]Migrating from {source_provider.upper()} to {target_provider.upper()}[/bold]"
        )
        if dry_run:
            console.print("[yellow]DRY RUN MODE - No files will be migrated[/yellow]")
        console.print()

        # Create migrator
        migrator = StorageMigrator(
            source_config=source_config,
            target_config=target_config,
            database_handler=api_initializer.database_handler,
        )

        # Run migration
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            overall_task = progress.add_task("Migrating files...", total=1)

            stats = migrator.migrate_all_files(batch_size=batch_size, dry_run=dry_run)

            progress.update(overall_task, completed=1)

        # Display results
        console.print()
        console.print("[bold]Migration Results:[/bold]")
        console.print(f"  Total files: {stats['total_files']}")
        console.print(f"  Migrated: {stats['migrated_files']}")
        console.print(f"  Failed: {stats['failed_files']}")
        console.print(f"  Skipped: {stats['skipped_files']}")
        console.print(
            f"  Data transferred: {stats['migrated_size'] / (1024**3):.2f} GB"
        )

        if stats["failed_files"] > 0:
            console.print(
                f"[yellow]Warning: {stats['failed_files']} files failed to migrate[/yellow]"
            )
        else:
            console.print("[green]✓ Migration completed successfully![/green]")

    except Exception as e:
        console.print(f"[bold red]Migration failed: {str(e)}[/bold red]")


def run() -> None:
    constants.banner()
    cli()
