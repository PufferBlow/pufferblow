"""Setup command for configuring a PufferBlow server instance."""

from __future__ import annotations

import secrets
from dataclasses import dataclass

import typer
from loguru import logger
from rich.panel import Panel
from rich.prompt import Confirm, Prompt

from pufferblow.api.config.config_handler import ConfigHandler
from pufferblow.cli.common import (
    DatabaseCredentials,
    build_database_uri_from_credentials,
    console,
    ensure_database_exists,
    load_runtime,
)
from pufferblow.cli.setup_prompt import run_setup_wizard
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


def _launch_setup_wizard(has_existing_config: bool):
    """Run the interactive setup wizard using typer prompts."""
    return run_setup_wizard(has_existing_config=has_existing_config)


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


def _prompt_media_sfu_config() -> dict[str, str | int]:
    """Prompt user for media-sfu configuration."""
    bootstrap_secret = Prompt.ask("Bootstrap secret", password=True).strip()
    bootstrap_config_url = Prompt.ask(
        "Bootstrap config URL",
        default="http://localhost:7575/api/internal/v1/voice/bootstrap-config",
    ).strip()
    bind_addr = Prompt.ask("WebSocket bind address", default=":8787").strip()
    max_total_peers = int(
        Prompt.ask("Max total peers across all rooms", default="200").strip()
    )
    max_room_peers = int(
        Prompt.ask("Max peers per room", default="60").strip()
    )
    event_workers = int(
        Prompt.ask("Event workers", default="4").strip()
    )

    if not bootstrap_secret:
        logger.error("Bootstrap secret is required.")
        raise typer.Exit(code=1)

    return {
        "bootstrap_secret": bootstrap_secret,
        "bootstrap_config_url": bootstrap_config_url,
        "bind_addr": bind_addr,
        "max_total_peers": max_total_peers,
        "max_room_peers": max_room_peers,
        "event_workers": event_workers,
    }


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
    security_settings = _ensure_runtime_security_settings(config_handler=config_handler)
    _apply_server_configuration(server=server, is_update=False)

    # Write database config to config.toml
    db_config = {
        "host": credentials.host,
        "port": credentials.port,
        "username": credentials.username,
        "password": credentials.password,
        "database": credentials.database_name,
    }

    # Write media-sfu config to config.toml with the generated bootstrap secret
    bootstrap_secret = security_settings.get("RTC_BOOTSTRAP_SECRET") or str(
        api_initializer.database_handler.get_runtime_config(include_secrets=True).get(
            "RTC_BOOTSTRAP_SECRET", ""
        )
    )
    
    media_sfu_config = {
        "bootstrap_config_url": "http://localhost:7575/api/internal/v1/voice/bootstrap-config",
        "bootstrap_secret": bootstrap_secret,
        "bind_addr": ":8787",
        "max_total_peers": 200,
        "max_room_peers": 60,
        "room_end_grace_seconds": 15,
        "event_workers": 4,
        "event_queue_size": 4096,
        "http_timeout_seconds": 5,
        "ws_write_timeout_seconds": 4,
        "ws_ping_interval_seconds": 20,
        "ws_pong_wait_seconds": 45,
        "ws_read_limit_bytes": 1048576,
        "udp_port_min": 50000,
        "udp_port_max": 50199,
    }

    config_handler.write_config_toml(
        database_config=db_config,
        media_sfu_config=media_sfu_config,
    )

    auth_token = api_initializer.user_manager.sign_up(
        username=owner.username,
        password=owner.password,
        is_admin=True,
        is_owner=True,
    ).raw_auth_token

    console.print(
        Panel.fit(
            f"[bold green]{auth_token}[/bold green]\n\n"
            "[bold red]Store this owner auth token safely.[/bold red]\n\n"
            f"[bold cyan]RTC Bootstrap Secret:[/bold cyan] [bold green]{bootstrap_secret}[/bold green]\n"
            f"(saved to ~/.pufferblow/config.toml)",
            title="[bold yellow]Setup Complete[/bold yellow]",
            border_style="green",
        )
    )


def _is_default_secret(value: str | None) -> bool:
    """Return whether a secret value still looks default/insecure."""
    if value is None:
        return True
    normalized = value.strip().lower()
    if not normalized:
        return True
    return normalized.startswith("change-this-")


def _ensure_runtime_security_settings(*, config_handler: ConfigHandler) -> dict[str, str]:
    """
    Ensure critical runtime secrets are generated and persisted in DB.
    """
    runtime = api_initializer.database_handler.get_runtime_config(include_secrets=True)
    updates: dict[str, str] = {}

    if _is_default_secret(str(runtime.get("JWT_SECRET") or "")):
        updates["JWT_SECRET"] = secrets.token_urlsafe(48)
    if _is_default_secret(str(runtime.get("RTC_JOIN_SECRET") or "")):
        updates["RTC_JOIN_SECRET"] = secrets.token_urlsafe(48)
    if _is_default_secret(str(runtime.get("RTC_INTERNAL_SECRET") or "")):
        updates["RTC_INTERNAL_SECRET"] = secrets.token_urlsafe(48)
    if _is_default_secret(str(runtime.get("RTC_BOOTSTRAP_SECRET") or "")):
        updates["RTC_BOOTSTRAP_SECRET"] = secrets.token_urlsafe(48)

    if updates:
        config_handler.write_config(
            database_handler=api_initializer.database_handler,
            config_updates=updates,
            secret_keys=set(updates.keys()),
        )
        for key, value in updates.items():
            setattr(api_initializer.config, key, value)

    bootstrap_secret = updates.get("RTC_BOOTSTRAP_SECRET") or str(
        runtime.get("RTC_BOOTSTRAP_SECRET") or ""
    )

    return updates


def _run_server_only_setup(
    *, config_handler: ConfigHandler, server: ServerDetails, is_update: bool
) -> None:
    """Execute setup flow that only touches server metadata."""
    database_uri = config_handler.resolve_database_uri()
    if not database_uri:
        logger.error(
            "No bootstrap database URI found. Run `pufferblow setup` first."
        )
        raise typer.Exit(code=1)

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


def _run_media_sfu_only_setup(
    *, config_handler: ConfigHandler, media_sfu_config: dict[str, str | int]
) -> None:
    """Execute setup flow that only touches media-sfu configuration."""
    database_uri = config_handler.resolve_database_uri()
    if not database_uri:
        logger.error(
            "No bootstrap database URI found. Run `pufferblow setup` first."
        )
        raise typer.Exit(code=1)

    # Write media-sfu config to config.toml (don't touch database section)
    config_handler.write_config_toml(
        media_sfu_config=media_sfu_config,
    )

    console.print(
        Panel.fit(
            "[bold green]Media-SFU configuration updated successfully![/bold green]\n\n"
            f"[bold cyan]Bootstrap URL:[/bold cyan] {media_sfu_config['bootstrap_config_url']}\n"
            f"[bold cyan]Bind Address:[/bold cyan] {media_sfu_config['bind_addr']}\n"
            f"(Configuration saved to ~/.pufferblow/config.toml)",
            title="[bold yellow]Media-SFU Setup Complete[/bold yellow]",
            border_style="green",
        )
    )



def _run_setup_payload(payload, *, config_handler: ConfigHandler) -> None:
    """Execute setup using values produced by the setup wizard."""
    # Handle media-sfu only mode
    if payload.mode == "media_sfu_only":
        if payload.media_sfu_config is None:
            logger.error("No media-sfu configuration provided.")
            raise typer.Exit(code=1)
        _run_media_sfu_only_setup(
            config_handler=config_handler,
            media_sfu_config=payload.media_sfu_config,
        )
        return

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


def setup_command(
    is_setup_server: bool = typer.Option(
        False, "--setup-server", help="Only create initial server metadata."
    ),
    is_update_server: bool = typer.Option(
        False,
        "--update-server",
        help="Update existing server metadata (name, description, welcome message).",
    ),
    is_setup_media_sfu: bool = typer.Option(
        False,
        "--setup-media-sfu",
        help="Only configure media-sfu WebRTC server.",
    ),
) -> None:
    """Configure database, server metadata, and owner account."""
    config_handler = ConfigHandler()
    has_bootstrap_config = config_handler.resolve_database_uri() is not None

    # Validate that only one flag is used
    flags_used = sum([is_setup_server, is_update_server, is_setup_media_sfu])
    if flags_used > 1:
        logger.error("Choose only one of --setup-server, --update-server, or --setup-media-sfu.")
        raise typer.Exit(code=1)

    if is_setup_media_sfu:
        if not has_bootstrap_config:
            logger.error(
                "No bootstrap database URI found. Run `pufferblow setup` first."
            )
            raise typer.Exit(code=1)
        media_sfu_config = _prompt_media_sfu_config()
        _run_media_sfu_only_setup(
            config_handler=config_handler,
            media_sfu_config=media_sfu_config,
        )
        return

    if is_setup_server or is_update_server:
        server = _prompt_server_details()
        _run_server_only_setup(
            config_handler=config_handler,
            server=server,
            is_update=is_update_server,
        )
        return

    payload = _launch_setup_wizard(has_existing_config=has_bootstrap_config)
    if payload is None:
        console.print("[dim]Setup cancelled.[/dim]")
        raise typer.Exit(code=0)

    _run_setup_payload(payload, config_handler=config_handler)
