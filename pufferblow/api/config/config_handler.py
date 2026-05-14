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


def _config_list(raw_value: object) -> tuple[str, ...]:
    """Normalize config values written as a TOML list or comma-separated string."""
    if raw_value is None:
        return ()

    if isinstance(raw_value, str):
        parts = [item.strip() for item in raw_value.split(",")]
        return tuple(item for item in parts if item)

    if isinstance(raw_value, (list, tuple)):
        normalized = []
        for item in raw_value:
            value = str(item).strip()
            if value:
                normalized.append(value)
        return tuple(normalized)

    value = str(raw_value).strip()
    return (value,) if value else ()


def _config_bool(raw_value: object, fallback: bool) -> bool:
    """Normalize config booleans and common string representations."""
    if raw_value is None:
        return fallback
    if isinstance(raw_value, bool):
        return raw_value
    if isinstance(raw_value, str):
        normalized = raw_value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    return bool(raw_value)


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
        Resolve database URI in priority order:

        1. ``~/.pufferblow/config.toml`` ``[database]`` section
           - explicit ``database_uri = "..."``, OR
           - individual ``host`` / ``port`` / ``username`` / ``password`` /
             ``database`` keys (assembled into a postgresql:// URI).
        2. ``PUFFERBLOW_DATABASE_URI`` environment variable.

        Returns ``None`` if neither source resolves a URI.

        The env var fallback exists so the Docker Compose stack can run
        `pufferblow serve` without first sshing into the container to
        run `pufferblow setup` — the compose file already exports this
        variable to both the server and the media-sfu sidecar.
        """
        # Source 1: config.toml [database]
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

        # Source 2: PUFFERBLOW_DATABASE_URI environment variable.
        env_uri = os.getenv("PUFFERBLOW_DATABASE_URI", "").strip()
        if env_uri:
            return env_uri

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
        security_config = config_toml.get("security", {})

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
        config.CORS_ALLOWED_ORIGINS = _config_list(
            security_config.get("cors_origins")
            if isinstance(security_config, dict)
            else None
        )
        cors_origin_regex = (
            str(security_config.get("cors_origin_regex", "")).strip()
            if isinstance(security_config, dict)
            else ""
        )
        config.CORS_ALLOWED_ORIGIN_REGEX = cors_origin_regex or None
        config.CORS_ALLOWED_METHODS = _config_list(
            security_config.get("cors_allow_methods")
            if isinstance(security_config, dict)
            else None
        ) or config.CORS_ALLOWED_METHODS
        config.CORS_ALLOWED_HEADERS = _config_list(
            security_config.get("cors_allow_headers")
            if isinstance(security_config, dict)
            else None
        ) or config.CORS_ALLOWED_HEADERS
        config.CORS_ALLOW_CREDENTIALS = _config_bool(
            security_config.get("cors_allow_credentials")
            if isinstance(security_config, dict)
            else None,
            config.CORS_ALLOW_CREDENTIALS,
        )

        # Backup settings
        backup_section = config_toml.get("backup", {})
        if isinstance(backup_section, dict):
            config.BACKUP_ENABLED = _config_bool(backup_section.get("enabled"), False)
            config.BACKUP_MODE = str(backup_section.get("mode", "file"))
            if backup_section.get("path"):
                config.BACKUP_PATH = str(backup_section["path"])
            if backup_section.get("mirror_dsn"):
                config.BACKUP_MIRROR_DSN = str(backup_section["mirror_dsn"])
            if backup_section.get("schedule_hours"):
                try:
                    config.BACKUP_SCHEDULE_HOURS = int(backup_section["schedule_hours"])
                except (ValueError, TypeError):
                    pass
            if backup_section.get("max_files"):
                try:
                    config.BACKUP_MAX_FILES = int(backup_section["max_files"])
                except (ValueError, TypeError):
                    pass

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

        # config.toml [media-sfu] is the shared file that media-sfu itself reads, so
        # it is the authoritative source for bootstrap/internal/join secrets. Re-apply
        # after DB hydration so a stale DB value can never shadow a config.toml update.
        self._overlay_media_sfu_secrets(config)
        return config

    def _overlay_media_sfu_secrets(self, config: Config) -> None:
        """Re-apply [media-sfu] secrets from config.toml, overriding any DB values."""
        toml = self._load_config_toml()
        section = toml.get("media-sfu", {})
        if not isinstance(section, dict):
            return
        mapping = {
            "bootstrap_secret": "RTC_BOOTSTRAP_SECRET",
            "internal_secret": "RTC_INTERNAL_SECRET",
            "join_secret": "RTC_JOIN_SECRET",
        }
        for toml_key, config_key in mapping.items():
            value = section.get(toml_key)
            if value and isinstance(value, str) and value.strip():
                setattr(config, config_key, value.strip())

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
        security_config: dict[str, object] | None = None,
        backup_config: dict[str, object] | None = None,
    ) -> None:
        """
        Write or update the shared Pufferblow config.toml.
        
        Args:
            database_config: Dict with keys like host, port, username, password, database
            media_sfu_config: Dict for the shared config [media-sfu] section
                (bootstrap_secret, bind_addr, and related SFU settings)
            security_config: Dict for the shared config [security] section
        """
        # Read existing config if it exists
        existing_config = self._load_config_toml()
        
        # Update database section if provided
        if database_config:
            existing_config["database"] = database_config
        
        # Update the shared config [media-sfu] section if provided.
        if media_sfu_config:
            existing_config["media-sfu"] = media_sfu_config

        if security_config:
            current_security = existing_config.get("security", {})
            if not isinstance(current_security, dict):
                current_security = {}
            for key, value in security_config.items():
                if value is None:
                    current_security.pop(key, None)
                    continue
                current_security[key] = value
            existing_config["security"] = current_security

        if backup_config:
            existing_config["backup"] = backup_config

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
        return f"{key} = {self._format_toml_value(value)}"

    def _format_toml_value(self, value: object) -> str:
        """Format a TOML value with basic support for arrays."""
        if isinstance(value, str):
            escaped = value.replace("\\", "\\\\").replace('"', '\\"')
            return f'"{escaped}"'
        if isinstance(value, bool):
            return str(value).lower()
        if isinstance(value, (int, float)):
            return str(value)
        if isinstance(value, (list, tuple)):
            rendered_items = ", ".join(self._format_toml_value(item) for item in value)
            return f"[{rendered_items}]"
        return f'"{value}"'
