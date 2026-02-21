"""Interactive prompt-based setup wizard using typer.

Type-hint driven CLI with simple prompt-based navigation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

import typer
from loguru import logger
from rich.console import Console

console = Console()


class SetupMode(str, Enum):
    """Setup mode options."""

    FULL = "full"
    SERVER_ONLY = "server_only"
    SERVER_UPDATE = "server_update"
    MEDIA_SFU_ONLY = "media_sfu_only"



@dataclass
class SetupWizardResult:
    """Result from setup wizard prompts."""

    mode: str
    database_name: str
    database_username: str
    database_password: str
    database_host: str
    database_port: str
    server_name: str
    server_description: str
    server_welcome_message: str
    owner_username: str
    owner_password: str
    media_sfu_config: dict[str, str | int] | None = None


def _get_setup_mode(has_existing_config: bool) -> str | None:
    """Prompt for setup mode."""
    console.print("\n[bold cyan]Setup Mode[/bold cyan]")
    console.print("1. Full setup (database + server + owner account)")

    menu_offset = 2
    if has_existing_config:
        console.print("2. Server configuration only (update existing database)")
        console.print("3. Update existing server information")
        console.print("4. Media-SFU configuration only")
        menu_offset = 5

    while True:
        choice = typer.prompt(
            "Select option",
            type=int,
        )

        if choice == 1:
            return SetupMode.FULL.value
        elif has_existing_config and choice == 2:
            return SetupMode.SERVER_ONLY.value
        elif has_existing_config and choice == 3:
            return SetupMode.SERVER_UPDATE.value
        elif has_existing_config and choice == 4:
            return SetupMode.MEDIA_SFU_ONLY.value
        else:
            console.print("[red]Invalid choice. Please try again.[/red]")



def _get_database_config() -> dict[str, str] | None:
    """Prompt for database credentials."""
    console.print("\n[bold cyan]Database Configuration[/bold cyan]")

    try:
        database_name = typer.prompt(
            "PostgreSQL database name",
            default="pufferblow",
        )

        username = typer.prompt(
            "PostgreSQL username",
            default="pufferblow",
        )

        password = typer.prompt(
            "PostgreSQL password",
            hide_input=True,
        )

        host = typer.prompt(
            "PostgreSQL host",
            default="localhost",
        )

        port = typer.prompt(
            "PostgreSQL port",
            default="5432",
        )

        return {
            "database_name": database_name,
            "username": username,
            "password": password,
            "host": host,
            "port": port,
        }
    except (EOFError, KeyboardInterrupt):
        return None

def _get_server_config() -> dict[str, str] | None:
    """Prompt for server metadata."""
    console.print("\n[bold cyan]Server Configuration[/bold cyan]")

    try:
        server_name = typer.prompt(
            "Server name",
        )

        if not server_name:
            console.print("[red]Please enter a server name[/red]")
            return None

        description = typer.prompt(
            "Server description",
        )

        if not description:
            console.print("[red]Please enter a description[/red]")
            return None

        welcome_message = typer.prompt(
            "Server welcome message",
        )

        if not welcome_message:
            console.print("[red]Please enter a welcome message[/red]")
            return None

        return {
            "server_name": server_name,
            "server_description": description,
            "server_welcome_message": welcome_message,
        }
    except (EOFError, KeyboardInterrupt):
        return None


def _get_owner_config() -> dict[str, str] | None:
    """Prompt for owner account credentials."""
    console.print("\n[bold cyan]Owner Account[/bold cyan]")

    try:
        username = typer.prompt(
            "Owner username",
        )

        if not username:
            console.print("[red]Please enter a username[/red]")
            return None

        while True:
            password = typer.prompt(
                "Owner password",
                hide_input=True,
            )

            if not password:
                console.print("[red]Please enter a password[/red]")
                continue

            confirm = typer.prompt(
                "Confirm password",
                hide_input=True,
            )

            if confirm == password:
                break
            else:
                console.print("[red]Passwords do not match. Try again.[/red]")

        return {
            "owner_username": username,
            "owner_password": password,
        }
    except (EOFError, KeyboardInterrupt):
        return None


def _confirm_test_database(host: str, port: str, username: str, password: str, database: str) -> bool:
    """Prompt to test database connection."""
    try:
        confirm = typer.confirm(
            "Test database connection before continuing?",
            default=True,
        )
        return confirm
    except (EOFError, KeyboardInterrupt):
        return False


def _get_media_sfu_config() -> dict[str, str | int] | None:
    """Prompt for media-sfu configuration."""
    console.print("\n[bold cyan]Media-SFU Configuration[/bold cyan]")

    try:
        bootstrap_secret = typer.prompt(
            "Bootstrap secret",
            hide_input=True,
        )

        if not bootstrap_secret:
            console.print("[red]Please enter a bootstrap secret[/red]")
            return None

        bootstrap_config_url = typer.prompt(
            "Bootstrap config URL",
            default="http://localhost:7575/api/internal/v1/voice/bootstrap-config",
        )

        bind_addr = typer.prompt(
            "WebSocket bind address",
            default=":8787",
        )

        max_total_peers = typer.prompt(
            "Max total peers across all rooms",
            type=int,
            default=200,
        )

        max_room_peers = typer.prompt(
            "Max peers per room",
            type=int,
            default=60,
        )

        event_workers = typer.prompt(
            "Event workers",
            type=int,
            default=4,
        )

        return {
            "bootstrap_secret": bootstrap_secret,
            "bootstrap_config_url": bootstrap_config_url,
            "bind_addr": bind_addr,
            "max_total_peers": max_total_peers,
            "max_room_peers": max_room_peers,
            "event_workers": event_workers,
        }
    except (EOFError, KeyboardInterrupt):
        return None


def run_setup_wizard(has_existing_config: bool) -> SetupWizardResult | None:
    """Run the interactive setup wizard.

    Returns:
        SetupWizardResult with all collected values, or None if cancelled.
    """
    console.print("\n[bold green]PufferBlow Server Setup Wizard[/bold green]\n")

    try:
        # Step 1: Mode selection
        mode = _get_setup_mode(has_existing_config)
        if mode is None:
            console.print("[dim]Setup cancelled.[/dim]")
            return None

        # Handle media-sfu only mode separately
        if mode == SetupMode.MEDIA_SFU_ONLY.value:
            media_sfu_config = _get_media_sfu_config()
            if media_sfu_config is None:
                return None

            # Summary
            console.print("\n[bold cyan]Media-SFU Configuration Summary[/bold cyan]")
            console.print(f"  Bootstrap URL: {media_sfu_config['bootstrap_config_url']}")
            console.print(f"  Bind Address: {media_sfu_config['bind_addr']}")
            console.print(f"  Max Total Peers: {media_sfu_config['max_total_peers']}")
            console.print(f"  Max Room Peers: {media_sfu_config['max_room_peers']}")

            if not typer.confirm("\nProceed with media-sfu configuration?", default=True):
                console.print("[dim]Setup cancelled.[/dim]")
                return None

            return SetupWizardResult(
                mode=mode,
                database_name="",
                database_username="",
                database_password="",
                database_host="",
                database_port="",
                server_name="",
                server_description="",
                server_welcome_message="",
                owner_username="",
                owner_password="",
                media_sfu_config=media_sfu_config,
            )

        # Step 2: Server configuration (needed for all other modes)
        server_config = _get_server_config()
        if server_config is None:
            return None

        # For server-only or update modes, we're done!
        if mode in (SetupMode.SERVER_ONLY.value, SetupMode.SERVER_UPDATE.value):
            return SetupWizardResult(
                mode=mode,
                database_name="",
                database_username="",
                database_password="",
                database_host="",
                database_port="",
                server_name=server_config["server_name"],
                server_description=server_config["server_description"],
                server_welcome_message=server_config["server_welcome_message"],
                owner_username="",
                owner_password="",
            )

        # Step 3: Database configuration (full setup only)
        db_config = _get_database_config()
        if db_config is None:
            return None

        # Optional: Test connection
        if _confirm_test_database(
            host=db_config["host"],
            port=db_config["port"],
            username=db_config["username"],
            password=db_config["password"],
            database=db_config["database_name"],
        ):
            try:
                import psycopg2

                conn = psycopg2.connect(
                    host=db_config["host"],
                    port=int(db_config["port"]),
                    user=db_config["username"],
                    password=db_config["password"],
                    database=db_config["database_name"],
                    connect_timeout=5,
                )
                conn.close()
                console.print("[green]✓ Database connection successful![/green]")
            except ImportError:
                console.print("[yellow]Note: psycopg2 not available, skipping test.[/yellow]")
            except Exception as e:
                console.print(f"[red]✗ Connection failed: {e}[/red]")
                if not typer.confirm("Continue anyway?", default=False):
                    return None

        # Step 4: Owner account (full setup only)
        owner_config = _get_owner_config()
        if owner_config is None:
            return None

        # Summary
        console.print("\n[bold cyan]Summary[/bold cyan]")
        console.print(f"  Server name: {server_config['server_name']}")
        console.print(f"  Database: {db_config['username']}@{db_config['host']}:{db_config['port']}/{db_config['database_name']}")
        console.print(f"  Owner user: {owner_config['owner_username']}")

        if not typer.confirm("\nProceed with setup?", default=True):
            console.print("[dim]Setup cancelled.[/dim]")
            return None

        return SetupWizardResult(
            mode=mode,
            database_name=db_config["database_name"],
            database_username=db_config["username"],
            database_password=db_config["password"],
            database_host=db_config["host"],
            database_port=db_config["port"],
            server_name=server_config["server_name"],
            server_description=server_config["server_description"],
            server_welcome_message=server_config["server_welcome_message"],
            owner_username=owner_config["owner_username"],
            owner_password=owner_config["owner_password"],
        )
    except (EOFError, KeyboardInterrupt):
        console.print("\n[dim]Setup cancelled.[/dim]")
        return None
