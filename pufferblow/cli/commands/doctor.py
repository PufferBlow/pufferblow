"""Read-only health check for a Pufferblow instance.

Run after an upgrade, after a config change, or when something looks
wrong. Touches:

  - PostgreSQL connectivity (using the bootstrap DATABASE_URI)
  - Schema drift (declared metadata vs live DB)
  - Storage backend (one upload/download/delete round-trip)
  - Runtime secrets (JWT_SECRET, RTC_*_SECRET) still at their
    setup-time defaults, which means the instance was never properly
    configured.

Everything is read-only except for the storage round-trip, which
writes and immediately deletes a single small file under
`cli-healthcheck/`. The check does NOT open the API port, register
background tasks, or start workers — so it's safe to run against a
production instance.

Exit code is 0 only if every check passes. Warnings on their own
don't fail the command, but errors do.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Literal

from loguru import logger

if TYPE_CHECKING:
    from pufferblow.api.models.config_model import Config

CheckLevel = Literal["pass", "warn", "fail"]


# Map our three CheckLevel values onto loguru levels so each check
# emission renders with the same color cue as elsewhere in the CLI:
# SUCCESS → green, WARNING → yellow, ERROR → red. Keeping the
# CheckLevel enum lets the helper signatures stay literal and small;
# only the emission layer cares about the loguru mapping.
_LOGURU_LEVEL: dict[CheckLevel, str] = {
    "pass": "SUCCESS",
    "warn": "WARNING",
    "fail": "ERROR",
}
_STATUS_TAG: dict[CheckLevel, str] = {
    "pass": "PASS",
    "warn": "WARN",
    "fail": "FAIL",
}


def _check_database(database_uri: str) -> tuple[CheckLevel, str]:
    """Confirm the API can open a connection against the bootstrap URI."""
    from pufferblow.api.database.database import Database

    try:
        if Database.check_database_existense(database_uri):
            return ("pass", "Connected to database.")
        return ("fail", "Database does not exist or is unreachable.")
    except Exception as exc:
        return ("fail", f"Database connectivity check raised: {exc}")


def _check_schema() -> tuple[CheckLevel, str]:
    """Report whether the live schema matches the declared metadata."""
    from pufferblow.cli.commands.migrate import _detect_schema_drift

    try:
        missing_tables, missing_columns = _detect_schema_drift()
    except Exception as exc:
        return ("fail", f"Schema introspection failed: {exc}")

    if not missing_tables and not missing_columns:
        return ("pass", "Schema is up to date.")

    parts: list[str] = []
    if missing_tables:
        parts.append(f"{len(missing_tables)} missing table(s)")
    if missing_columns:
        parts.append(f"{len(missing_columns)} missing column(s)")
    return (
        "fail",
        f"Schema drift: {' and '.join(parts)}. Run `pufferblow migrate`.",
    )


def _check_storage(config: Config) -> tuple[CheckLevel, str]:
    """Run an upload/download/delete cycle against the configured backend."""
    from pufferblow.api.storage.local_storage import LocalStorageBackend
    from pufferblow.api.storage.s3_storage import S3StorageBackend

    storage_config = {
        "provider": config.STORAGE_PROVIDER,
        "storage_path": config.STORAGE_PATH,
        "base_url": config.STORAGE_BASE_URL,
        "allocated_space_gb": config.STORAGE_ALLOCATED_GB,
        "bucket_name": getattr(config, "S3_BUCKET_NAME", None),
        "region": getattr(config, "S3_REGION", "us-east-1"),
        "access_key": getattr(config, "S3_ACCESS_KEY", None),
        "secret_key": getattr(config, "S3_SECRET_KEY", None),
        "endpoint_url": getattr(config, "S3_ENDPOINT_URL", None),
    }

    backend = (
        LocalStorageBackend(storage_config)
        if storage_config["provider"] == "local"
        else S3StorageBackend(storage_config)
    )
    test_path = "cli-healthcheck/test.txt"
    test_content = b"pufferblow doctor"

    async def cycle() -> None:
        await backend.upload_file(test_content, test_path)
        downloaded = await backend.download_file(test_path)
        if downloaded != test_content:
            raise RuntimeError("content mismatch on read-back")
        await backend.delete_file(test_path)

    try:
        asyncio.run(cycle())
    except Exception as exc:
        return ("fail", f"Storage round-trip failed: {exc}")

    return (
        "pass",
        f"Storage backend OK ({storage_config['provider']}).",
    )


def _check_secrets(config: Config) -> tuple[CheckLevel, str]:
    """Warn when runtime secrets still look like setup-time placeholders.

    The default-config strings start with 'change-this-'; if any of
    those are still in place the instance is reachable but unsafe to
    expose, so emit a hard failure rather than a warning.
    """
    fields = ("JWT_SECRET", "RTC_JOIN_SECRET", "RTC_INTERNAL_SECRET", "RTC_BOOTSTRAP_SECRET")
    stale = [
        name for name in fields
        if str(getattr(config, name, "") or "").strip().lower().startswith("change-this-")
    ]
    if not stale:
        return ("pass", "Runtime secrets look populated.")
    return (
        "fail",
        f"Default secrets in use: {', '.join(stale)}. Run `pufferblow setup` to regenerate.",
    )


def _check_media_sfu(config: Config) -> tuple[CheckLevel, str]:
    """Report whether the media-sfu side of the config has been filled in."""
    secret = str(getattr(config, "RTC_BOOTSTRAP_SECRET", "") or "")
    bootstrap_url = getattr(config, "RTC_BOOTSTRAP_CONFIG_URL", None)
    if secret.lower().startswith("change-this-") or not secret:
        return (
            "warn",
            "media-sfu bootstrap secret not configured. Voice channels will not work.",
        )
    if not bootstrap_url:
        return (
            "warn",
            "RTC_BOOTSTRAP_CONFIG_URL is empty. Voice channels will not work.",
        )
    return ("pass", "media-sfu bootstrap fields look populated.")


def doctor_command() -> None:
    """Run a read-only health check across the instance."""
    from pufferblow.api.config.config_handler import ConfigHandler
    from pufferblow.cli.common import (
        configure_cli_logging,
        ensure_database_exists,
        load_config_or_exit,
        load_runtime,
    )

    configure_cli_logging()
    config = load_config_or_exit()

    database_uri = ConfigHandler().resolve_database_uri()
    if not database_uri:
        logger.error("No bootstrap database URI found. Run `pufferblow setup` first.")
        raise SystemExit(1)

    ensure_database_exists(database_uri)
    load_runtime(database_uri=database_uri, setup_tables=False)
    from pufferblow.core.bootstrap import api_initializer

    runtime_config = api_initializer.config

    # Each entry: (name, (level, message)). The order is deliberate —
    # DB → schema → storage → secrets → media-sfu reads as a checklist
    # from "is the service reachable at all" to "is voice ready".
    checks: list[tuple[str, tuple[CheckLevel, str]]] = [
        ("Database", _check_database(database_uri)),
        ("Schema", _check_schema()),
        ("Storage", _check_storage(runtime_config)),
        ("Secrets", _check_secrets(runtime_config)),
        ("Media SFU", _check_media_sfu(runtime_config)),
    ]

    failed = False
    for name, (level, message) in checks:
        if level == "fail":
            failed = True
        # Pad the check name so the four-character status tag lines
        # up across rows ("Database  PASS  …" reads cleanly even
        # under the longer "Media SFU" label).
        logger.log(
            _LOGURU_LEVEL[level],
            "{name:<10} {status}  {detail}",
            name=name,
            status=_STATUS_TAG[level],
            detail=message,
        )

    if failed:
        logger.error("One or more checks failed.")
        raise SystemExit(1)

    logger.success("All checks passed.")
