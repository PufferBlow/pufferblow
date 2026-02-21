from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pufferblow.core.constants as constants
from pufferblow.api.models.config_model import Config

# Use tomllib (Python 3.11+) or tomli (fallback)
if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

if TYPE_CHECKING:
    from pufferblow.api.database.database_handler import DatabaseHandler


def _env_int(name: str, fallback: int) -> int:
    """Read integer env var and return fallback when missing/invalid."""
    raw_value = os.getenv(name, "").strip()
    if not raw_value:
        return fallback
    try:
        return int(raw_value)
    except ValueError:
        return fallback


class ConfigHandler:
    """Load bootstrap config and persist runtime config in database."""

    def __init__(self) -> None:
        """Initialize configuration directory paths."""
        self.root_state_dir = Path(f"{constants.HOME}/.pufferblow")
        self.config_toml_path = self.root_state_dir / "config.toml"
        self.root_state_dir.mkdir(parents=True, exist_ok=True)

    def _load_config_toml(self) -> dict[str, object]:
        """Load config.toml file from ~/.pufferblow/config.toml."""
        if not self.config_toml_path.exists():
            return {}

        try:
            with open(self.config_toml_path, "rb") as f:
                return tomllib.load(f)
        except Exception as e:
            print(f"Warning: Failed to load config.toml: {e}", file=__import__("sys").stderr)
            return {}

    def resolve_database_uri(self) -> str | None:
        """
        Resolve database URI from config.toml [database] section.
        
        Reads database configuration from ~/.pufferblow/config.toml [database] section.
        Supports two formats:
        - Full URI: database_uri = "postgresql://..."
        - Individual params: host, port, username, password, database
        
        Returns None if config.toml or database section not found.
        """
        # Load from config.toml only
        config = self._load_config_toml()
        if config.get("database"):
            db_config = config["database"]
            
            # Approach 1: Full URI in config.toml
            if "database_uri" in db_config:
                uri = str(db_config.get("database_uri", "")).strip()
                if uri:
                    return uri
            
            # Approach 2: Build URI from individual parameters
            host = db_config.get("host", "localhost")
            port = db_config.get("port", 5432)
            username = db_config.get("username", "pufferblow")
            password = db_config.get("password", "")
            database = db_config.get("database", "pufferblow")
            
            if all([host, username, password, database]):
                uri = f"postgresql://{username}:{password}@{host}:{port}/{database}"
                return uri
        
        return None

    def check_config(self) -> bool:
        """
        Check whether minimal bootstrap configuration exists.
        """
        return self.resolve_database_uri() is not None

    def build_bootstrap_config(self) -> Config:
        """
        Build in-memory config for startup from minimal bootstrap surface.
        Loads from (in priority order): config.toml, environment variables, defaults.
        """
        config = Config()
        config_toml = self._load_config_toml()

        # Network/process bootstrap values
        # Priority: config.toml > env var > default
        config.API_HOST = (
            config_toml.get("server", {}).get("api_host")
            or os.getenv("PUFFERBLOW_API_HOST")
            or config.API_HOST
        )
        config.API_PORT = (
            config_toml.get("server", {}).get("api_port")
            or _env_int("PUFFERBLOW_API_PORT", int(config.API_PORT))
        )
        config.WORKERS = (
            config_toml.get("server", {}).get("workers")
            or _env_int("PUFFERBLOW_WORKERS", int(config.WORKERS))
        )
        config.LOGS_PATH = (
            config_toml.get("server", {}).get("logs_path")
            or os.getenv(
                "PUFFERBLOW_LOGS_PATH",
                f"{constants.HOME}/.pufferblow/logs/pufferblow.log",
            )
        )
        return config

    def load_config(
        self, database_handler: DatabaseHandler | None = None
    ) -> dict[str, object]:
        """
        Return runtime config map from database or bootstrap defaults.
        """
        if database_handler is None:
            bootstrap = self.build_bootstrap_config()
            return {
                name: getattr(bootstrap, name)
                for name in bootstrap.__class__.__dict__.keys()
                if name.isupper()
            }

        runtime = database_handler.get_runtime_config(include_secrets=True)
        if runtime:
            return runtime

        bootstrap = self.build_bootstrap_config()
        return {
            name: getattr(bootstrap, name)
            for name in bootstrap.__class__.__dict__.keys()
            if name.isupper()
        }

    def hydrate_config_from_database(
        self, *, database_handler: DatabaseHandler, config: Config
    ) -> Config:
        """
        Apply runtime settings from database on top of the bootstrap config model.
        """
        runtime_values = database_handler.get_runtime_config(include_secrets=True)
        if not runtime_values:
            return config

        for key, value in runtime_values.items():
            if hasattr(config, key):
                setattr(config, key, value)
        return config

    def write_config(
        self,
        *,
        database_handler: DatabaseHandler,
        config_updates: dict[str, object],
        secret_keys: set[str] | None = None,
    ) -> None:
        """
        Persist runtime config updates in database.
        """
        database_handler.update_runtime_config(
            settings_updates=config_updates,
            secret_keys=secret_keys,
        )
    def write_config_toml(
        self,
        database_config: dict[str, str] | None = None,
        media_sfu_config: dict[str, object] | None = None,
    ) -> None:
        """
        Write or update config.toml with database and media-sfu sections.
        
        Args:
            database_config: Dict with keys like host, port, username, password, database
            media_sfu_config: Dict with media-sfu configuration (bootstrap_secret, bind_addr, etc.)
        """
        # Read existing config if it exists
        existing_config = self._load_config_toml()
        
        # Update database section if provided
        if database_config:
            existing_config["database"] = database_config
        
        # Update media-sfu section if provided
        if media_sfu_config:
            existing_config["media-sfu"] = media_sfu_config
        
        # Convert to TOML and write
        toml_content = self._dict_to_toml_string(existing_config)
        self.config_toml_path.write_text(toml_content, encoding="utf-8")
        self.config_toml_path.chmod(0o600)  # Restrict to owner only

    def _dict_to_toml_string(self, data: dict[str, object]) -> str:
        """Convert a dictionary to TOML format string."""
        lines = []
        
        for key, value in data.items():
            if isinstance(value, dict):
                lines.append(f"\n[{key}]")
                for sub_key, sub_value in value.items():
                    lines.append(self._format_toml_line(sub_key, sub_value))
            elif not key.startswith("_"):
                lines.append(self._format_toml_line(key, value))
        
        return "\n".join(lines) + "\n\n"

    def _format_toml_line(self, key: str, value: object) -> str:
        """Format a single key-value pair for TOML."""
        if isinstance(value, str):
            # Escape backslashes and quotes
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            return f'{key} = "{escaped}"'
        elif isinstance(value, bool):
            return f"{key} = {str(value).lower()}"
        elif isinstance(value, (int, float)):
            return f"{key} = {value}"
        elif isinstance(value, list):
            return f"{key} = {value}"
        else:
            return f'{key} = "{value}"'