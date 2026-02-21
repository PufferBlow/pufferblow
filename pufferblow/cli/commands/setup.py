"""Setup command for configuring a PufferBlow server instance."""

from __future__ import annotations

from dataclasses import dataclass

import typer
from loguru import logger
from rich.panel import Panel
from rich.prompt import Confirm, Prompt

from pufferblow.api.config.config_handler import ConfigHandler
from pufferblow.api.models.config_model import Config
from pufferblow.cli.common import (
    DatabaseCredentials,
    build_database_uri_from_config,
    build_database_uri_from_credentials,
    console,
    ensure_database_exists,
    load_runtime,
)
from pufferblow.core.bootstrap import api_initializer


@dataclass(slots=True)
class ServerDetails:
    """Server information collected from setup flow."""

    name: str
    description: str
    welcome_message: str


@dataclass(slots=True)
class OwnerDetails:
    """Owner account information collected from setup flow."""

    username: str
    password: str


def _launch_textual_setup(has_existing_config: bool):
    """Run the Textual setup wizard when available."""
    try:
        from pufferblow.cli.textual_setup import SetupWizardApp
    except ImportError:
        return ("missing_dependency", None)

    app = SetupWizardApp(has_existing_config=has_existing_config)
    app.run()
    if app.result is None:
        return ("cancelled", None)
    return ("ok", app.result)


def _prompt_database_credentials() -> DatabaseCredentials:
    """Prompt user for PostgreSQL connection details."""
    database_name = Prompt.ask("PostgreSQL database name", default="postgres").strip()
    username = Prompt.ask("PostgreSQL username").strip()
    password = Prompt.ask("PostgreSQL password", password=True)
    host = Prompt.ask("PostgreSQL host", default="localhost").strip()
    port_raw = Prompt.ask("PostgreSQL port", default="5432").strip()

    if not port_raw.isdigit():
        logger.error("Database port must be numeric.")
        raise typer.Exit(code=1)

    return DatabaseCredentials(
        database_name=database_name,
        username=username,
        password=password,
        host=host,
        port=int(port_raw),
    )


def _prompt_server_details() -> ServerDetails:
    """Prompt user for server metadata."""
    name = Prompt.ask("Server name").strip()
    description = Prompt.ask("Server description").strip()
    welcome_message = Prompt.ask("Server welcome message").strip()

    if not name or not description or not welcome_message:
        logger.error("Server name, description, and welcome message are required.")
        raise typer.Exit(code=1)

    return ServerDetails(
        name=name,
        description=description,
        welcome_message=welcome_message,
    )


def _prompt_owner_details() -> OwnerDetails:
    """Prompt user for owner account credentials."""
    username = Prompt.ask("Owner username").strip()
    password = Prompt.ask("Owner password", password=True)

    if not username or not password:
        logger.error("Owner username and password are required.")
        raise typer.Exit(code=1)

    return OwnerDetails(username=username, password=password)


def _apply_server_configuration(
    *, server: ServerDetails, is_update: bool
) -> None:
    """Create or update server information."""
    if is_update:
        api_initializer.server_manager.update_server(
            server_name=server.name,
            description=server.description,
            server_welcome_message=server.welcome_message,
        )
        return

    api_initializer.server_manager.create_server(
        server_name=server.name,
        description=server.description,
        server_welcome_message=server.welcome_message,
    )


def _save_database_config(
    *, config_handler: ConfigHandler, credentials: DatabaseCredentials
) -> Config:
    """Persist database settings to config file and return config model."""
    config = Config()
    config.DATABASE_NAME = credentials.database_name
    config.USERNAME = credentials.username
    config.DATABASE_PASSWORD = credentials.password
    config.DATABASE_HOST = credentials.host
    config.DATABASE_PORT = credentials.port
    config_handler.write_config(config=config.export_toml())
    return config


def _run_full_setup(
    *,
    config_handler: ConfigHandler,
    credentials: DatabaseCredentials,
    server: ServerDetails,
    owner: OwnerDetails,
) -> None:
    """Execute first-time setup workflow."""
    database_uri = build_database_uri_from_credentials(credentials)
    ensure_database_exists(database_uri)
    load_runtime(database_uri=database_uri)

    if api_initializer.server_manager.check_server_exists():
        logger.error(
            "Server already exists for this database. Use --update-server for changes."
        )
        raise typer.Exit(code=1)

    api_initializer.database_handler.initialize_default_data()
    _apply_server_configuration(server=server, is_update=False)

    auth_token = api_initializer.user_manager.sign_up(
        username=owner.username,
        password=owner.password,
        is_admin=True,
        is_owner=True,
    ).raw_auth_token

    _save_database_config(config_handler=config_handler, credentials=credentials)

    console.print(
        Panel.fit(
            f"[bold green]{auth_token}[/bold green]\n\n"
            "[bold red]Store this owner auth token safely.[/bold red]",
            title="[bold yellow]Setup Complete[/bold yellow]",
            border_style="green",
        )
    )


def _run_server_only_setup(
    *, config_handler: ConfigHandler, server: ServerDetails, is_update: bool
) -> None:
    """Execute setup flow that only touches server metadata."""
    if not config_handler.check_config():
        logger.error(
            "No config file found. Run full setup before using --setup-server/--update-server."
        )
        raise typer.Exit(code=1)

    config = Config(config=config_handler.load_config())
    database_uri = build_database_uri_from_config(config)
    ensure_database_exists(database_uri)
    load_runtime(database_uri=database_uri)

    if not is_update and api_initializer.server_manager.check_server_exists():
        logger.error("Server already exists. Use --update-server to modify it.")
        raise typer.Exit(code=1)

    _apply_server_configuration(server=server, is_update=is_update)
    logger.info(
        "Server information {action} successfully.",
        action="updated" if is_update else "created",
    )


def _run_textual_payload(payload, *, config_handler: ConfigHandler) -> None:
    """Execute setup using values produced by Textual setup app."""
    server = ServerDetails(
        name=payload.server_name,
        description=payload.server_description,
        welcome_message=payload.server_welcome_message,
    )

    if payload.mode == "full":
        credentials = DatabaseCredentials(
            database_name=payload.database_name,
            username=payload.database_username,
            password=payload.database_password,
            host=payload.database_host or "localhost",
            port=int(payload.database_port or "5432"),
        )
        owner = OwnerDetails(
            username=payload.owner_username,
            password=payload.owner_password,
        )
        _run_full_setup(
            config_handler=config_handler,
            credentials=credentials,
            server=server,
            owner=owner,
        )
        return

    _run_server_only_setup(
        config_handler=config_handler,
        server=server,
        is_update=payload.mode == "server_update",
    )


def _prompt_mode_without_textual(has_config: bool) -> str:
    """Prompt for setup mode when Textual is unavailable."""
    console.print("[bold]Setup mode[/bold]")
    console.print("1. Full setup (database + server + owner)")
    if has_config:
        console.print("2. Server configuration only")
        console.print("3. Update existing server information")
        choices = ["1", "2", "3"]
    else:
        choices = ["1"]
    selected = Prompt.ask("Select mode", choices=choices, default="1")
    if selected == "2":
        return "server_only"
    if selected == "3":
        return "server_update"
    return "full"


def setup_command(
    is_setup_server: bool = typer.Option(
        False, "--setup-server", help="Only create initial server metadata."
    ),
    is_update_server: bool = typer.Option(
        False,
        "--update-server",
        help="Update existing server metadata (name, description, welcome message).",
    ),
) -> None:
    """Configure database, server metadata, and owner account."""
    config_handler = ConfigHandler()
    has_config = config_handler.check_config()

    if is_setup_server and is_update_server:
        logger.error("Choose either --setup-server or --update-server, not both.")
        raise typer.Exit(code=1)

    if is_setup_server or is_update_server:
        server = _prompt_server_details()
        _run_server_only_setup(
            config_handler=config_handler,
            server=server,
            is_update=is_update_server,
        )
        return

    setup_state, payload = _launch_textual_setup(has_existing_config=has_config)
    if setup_state == "ok":
        _run_textual_payload(payload, config_handler=config_handler)
        return
    if setup_state == "cancelled":
        console.print("[dim]Setup cancelled.[/dim]")
        raise typer.Exit(code=0)

    mode = _prompt_mode_without_textual(has_config=has_config)
    server = _prompt_server_details()

    if mode == "server_only":
        _run_server_only_setup(
            config_handler=config_handler,
            server=server,
            is_update=False,
        )
        return
    if mode == "server_update":
        _run_server_only_setup(
            config_handler=config_handler,
            server=server,
            is_update=True,
        )
        return

    if has_config and not Confirm.ask(
        "Config file exists. Do you want to continue and overwrite database settings?",
        default=False,
    ):
        raise typer.Exit(code=0)

    credentials = _prompt_database_credentials()
    owner = _prompt_owner_details()
    _run_full_setup(
        config_handler=config_handler,
        credentials=credentials,
        server=server,
        owner=owner,
    )
