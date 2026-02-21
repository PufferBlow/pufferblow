from __future__ import annotations

import json
import os
from pathlib import Path
from typing import TYPE_CHECKING

import pufferblow.core.constants as constants
from pufferblow.api.models.config_model import Config

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
        """Initialize bootstrap state directory and file path."""
        self.root_state_dir = Path(f"{constants.HOME}/.pufferblow")
        self.bootstrap_state_path = self.root_state_dir / "bootstrap_state.json"
        self.root_state_dir.mkdir(parents=True, exist_ok=True)

    def _load_bootstrap_state(self) -> dict[str, object]:
        """Load persisted local bootstrap state from disk."""
        if not self.bootstrap_state_path.exists():
            return {}

        try:
            return json.loads(self.bootstrap_state_path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def _save_bootstrap_state(self, payload: dict[str, object]) -> None:
        """Save local bootstrap state file."""
        self.bootstrap_state_path.write_text(
            json.dumps(payload, indent=2),
            encoding="utf-8",
        )

    def set_bootstrap_database_uri(self, database_uri: str) -> None:
        """
        Persist bootstrap database URI for future non-interactive startup.
        """
        state = self._load_bootstrap_state()
        state["database_uri"] = database_uri
        self._save_bootstrap_state(state)

    def set_bootstrap_sfu_secret(self, bootstrap_secret: str) -> None:
        """
        Persist SFU bootstrap secret for local deployment tooling.
        """
        state = self._load_bootstrap_state()
        state["rtc_bootstrap_secret"] = bootstrap_secret
        self._save_bootstrap_state(state)

    def resolve_bootstrap_sfu_secret(self) -> str | None:
        """
        Resolve locally stored SFU bootstrap secret.
        """
        state = self._load_bootstrap_state()
        value = str(state.get("rtc_bootstrap_secret", "")).strip()
        return value or None

    def resolve_database_uri(self) -> str | None:
        """
        Resolve database URI from explicit env override or setup bootstrap state.
        """
        explicit_uri = os.getenv("PUFFERBLOW_DATABASE_URI", "").strip()
        if explicit_uri:
            return explicit_uri

        state = self._load_bootstrap_state()
        stored_uri = str(state.get("database_uri", "")).strip()
        return stored_uri or None

    def check_config(self) -> bool:
        """
        Check whether minimal bootstrap configuration exists.
        """
        return self.resolve_database_uri() is not None

    def build_bootstrap_config(self) -> Config:
        """
        Build in-memory config for startup from minimal bootstrap surface.
        """
        config = Config()

        # Network/process bootstrap values.
        config.API_HOST = os.getenv("PUFFERBLOW_API_HOST", config.API_HOST)
        config.API_PORT = _env_int("PUFFERBLOW_API_PORT", int(config.API_PORT))
        config.WORKERS = _env_int("PUFFERBLOW_WORKERS", int(config.WORKERS))
        config.LOGS_PATH = os.getenv(
            "PUFFERBLOW_LOGS_PATH",
            f"{constants.HOME}/.pufferblow/logs/pufferblow.log",
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
