"""Interactive prompt-based setup wizard using typer.

Type-hint driven CLI with simple prompt-based navigation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

import typer
from loguru import logger


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
    security_config: dict[str, object] | None = None
    media_sfu_config: dict[str, str | int] | None = None


def _get_setup_mode(has_existing_config: bool) -> str | None:
    """Prompt for setup mode."""
    logger.info("─── Setup mode ───")
    logger.info("1. Full setup (database + server + owner account)")

    if has_existing_config:
        logger.info("2. Server configuration only (update existing database)")
        logger.info("3. Update existing server information")
        logger.info("4. Shared Pufferblow config only ([media-sfu] section)")

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
            logger.error("Invalid choice. Please try again.")



def _get_database_config() -> dict[str, str] | None:
    """Prompt for database credentials."""
    logger.info("─── Database configuration ───")

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
    logger.info("─── Server configuration ───")

    try:
        server_name = typer.prompt(
            "Server name",
        )

        if not server_name:
            logger.error("Please enter a server name.")
            return None

        description = typer.prompt(
            "Server description",
        )

        if not description:
            logger.error("Please enter a description.")
            return None

        welcome_message = typer.prompt(
            "Server welcome message",
        )

        if not welcome_message:
            logger.error("Please enter a welcome message.")
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
    logger.info("─── Owner account ───")

    try:
        username = typer.prompt(
            "Owner username",
        )

        if not username:
            logger.error("Please enter a username.")
            return None

        while True:
            password = typer.prompt(
                "Owner password",
                hide_input=True,
            )

            if not password:
                logger.error("Please enter a password.")
                continue

            confirm = typer.prompt(
                "Confirm password",
                hide_input=True,
            )

            if confirm == password:
                break
            else:
                logger.error("Passwords do not match. Try again.")

        return {
            "owner_username": username,
            "owner_password": password,
        }
    except (EOFError, KeyboardInterrupt):
        return None


def _get_security_config() -> dict[str, object] | None:
    """Prompt for CORS settings stored in the shared config.toml."""
    logger.info("─── Client access (CORS) ───")
    logger.info("1. Allow any web client origin")
    logger.info("2. Allow one client origin")

    try:
        while True:
            choice = typer.prompt("Select option", type=int)
            if choice == 1:
                return {
                    "cors_origin_regex": ".*",
                    "cors_origins": [],
                    "cors_allow_credentials": True,
                    "cors_allow_methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                    "cors_allow_headers": ["*"],
                }

            if choice == 2:
                client_origin = typer.prompt(
                    "Client origin (include scheme and port when needed)",
                    default="http://localhost:5173",
                ).strip()
                if not client_origin:
                    logger.error("Please enter a client origin.")
                    continue

                return {
                    "cors_origin_regex": None,
                    "cors_origins": [client_origin],
                    "cors_allow_credentials": True,
                    "cors_allow_methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                    "cors_allow_headers": ["*"],
                }

            logger.error("Invalid choice. Please try again.")
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
    """Prompt for the shared Pufferblow config [media-sfu] section."""
    logger.info("─── Shared Pufferblow config: [media-sfu] ───")

    try:
        bootstrap_secret = typer.prompt(
            "Bootstrap secret",
            hide_input=True,
        )

        if not bootstrap_secret:
            logger.error("Please enter a bootstrap secret.")
            return None

        bootstrap_config_url = typer.prompt(
            "Bootstrap config URL",
            default="http://localhost:7575/api/internal/v1/voice/bootstrap-config",
        )

        # Default to 0.0.0.0 (not :port) so Windows binds IPv4 explicitly --
        # Go's bare ":8787" can resolve to "[::1]:8787" on Windows, which the
        # client (which dials 127.0.0.1:8787) can't reach. 0.0.0.0 also keeps
        # the Docker production setup working since the published port maps
        # through to the container's IPv4 listener.
        bind_addr = typer.prompt(
            "WebSocket bind address",
            default="0.0.0.0:8787",
        )

        max_total_peers = typer.prompt(
            "Max total peers across all rooms",
            type=int,
            default=1000,
        )

        max_room_peers = typer.prompt(
            "Max peers per room",
            type=int,
            default=100,
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
    logger.info("Pufferblow setup wizard.")

    try:
        # Step 1: Mode selection
        mode = _get_setup_mode(has_existing_config)
        if mode is None:
            logger.info("Setup cancelled.")
            return None

        # Handle media-sfu only mode separately
        if mode == SetupMode.MEDIA_SFU_ONLY.value:
            media_sfu_config = _get_media_sfu_config()
            if media_sfu_config is None:
                return None

            logger.info("─── Summary: [media-sfu] ───")
            logger.info(
                "  bootstrap_url={url}",
                url=media_sfu_config["bootstrap_config_url"],
            )
            logger.info("  bind_addr={addr}", addr=media_sfu_config["bind_addr"])
            logger.info(
                "  max_total_peers={n}", n=media_sfu_config["max_total_peers"]
            )
            logger.info("  max_room_peers={n}", n=media_sfu_config["max_room_peers"])

            if not typer.confirm(
                "Proceed with updating the shared Pufferblow config [media-sfu] section?",
                default=True,
            ):
                logger.info("Setup cancelled.")
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
                security_config=None,
                media_sfu_config=media_sfu_config,
            )

        # Step 2: Server configuration (needed for all other modes)
        server_config = _get_server_config()
        if server_config is None:
            return None

        security_config = _get_security_config()
        if security_config is None:
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
                security_config=security_config,
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
                logger.success("Database connection successful.")
            except ImportError:
                logger.warning("psycopg2 not available, skipping connection test.")
            except Exception as e:
                logger.error("Database connection failed: {err}", err=e)
                if not typer.confirm("Continue anyway?", default=False):
                    return None

        # Step 4: Owner account (full setup only)
        owner_config = _get_owner_config()
        if owner_config is None:
            return None

        logger.info("─── Summary ───")
        logger.info("  server_name={n}", n=server_config["server_name"])
        logger.info(
            "  database={user}@{host}:{port}/{name}",
            user=db_config["username"],
            host=db_config["host"],
            port=db_config["port"],
            name=db_config["database_name"],
        )
        logger.info("  owner_user={n}", n=owner_config["owner_username"])
        cors_summary = (
            "Any web client origin"
            if security_config.get("cors_origin_regex")
            else ", ".join(str(value) for value in security_config.get("cors_origins", []))
        )
        logger.info("  client_origins={c}", c=cors_summary)

        if not typer.confirm("Proceed with setup?", default=True):
            logger.info("Setup cancelled.")
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
            security_config=security_config,
        )
    except (EOFError, KeyboardInterrupt):
        logger.info("Setup cancelled.")
        return None
