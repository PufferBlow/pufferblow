"""Storage command group for backend setup, validation, and migration."""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from loguru import logger
from rich.prompt import Confirm, Prompt

from pufferblow.api.config.config_handler import ConfigHandler
from pufferblow.api.models.config_model import Config
from pufferblow.api.storage.local_storage import LocalStorageBackend
from pufferblow.api.storage.s3_storage import S3StorageBackend
from pufferblow.cli.common import console
from pufferblow.core.bootstrap import api_initializer


def _prompt_provider() -> str:
    """Prompt for selected storage provider."""
    console.print("[bold]Storage provider[/bold]")
    console.print("1. Local")
    console.print("2. AWS S3")
    console.print("3. S3 Compatible")
    console.print("4. Cancel")
    return Prompt.ask(
        "Select provider",
        choices=["1", "2", "3", "4"],
        default="1",
    )


def _prompt_local_config() -> dict:
    """Collect local storage options."""
    storage_path = Prompt.ask("Storage path", default="./storage").strip()
    if not Path(storage_path).is_absolute():
        storage_path = str((Path.cwd() / storage_path).resolve())
    allocated_gb_raw = Prompt.ask("Allocated storage (GB)", default="10").strip()
    try:
        allocated_gb = float(allocated_gb_raw)
        if allocated_gb <= 0:
            raise ValueError
    except ValueError:
        logger.error("Allocated storage must be a positive number.")
        raise typer.Exit(code=1)

    return {
        "provider": "local",
        "storage_path": storage_path,
        "allocated_space_gb": allocated_gb,
        "base_url": "/storage",
    }


def _prompt_s3_config(*, is_aws: bool) -> dict:
    """Collect S3 or S3-compatible options."""
    bucket_name = Prompt.ask("Bucket name").strip()
    region = Prompt.ask("Region", default="us-east-1").strip()
    access_key = Prompt.ask("Access key").strip()
    secret_key = Prompt.ask("Secret key", password=True)
    endpoint_url = None
    if not is_aws:
        endpoint_url = Prompt.ask("Endpoint URL").strip()

    if not bucket_name or not access_key or not secret_key:
        logger.error("Bucket name, access key, and secret key are required for S3.")
        raise typer.Exit(code=1)

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


def _save_storage_config(storage_config: dict) -> None:
    """Persist storage configuration in config file."""
    config_handler = ConfigHandler()
    config = (
        Config(config=config_handler.load_config())
        if config_handler.check_config()
        else Config()
    )

    config.STORAGE_PROVIDER = storage_config["provider"]
    config.STORAGE_PATH = storage_config.get("storage_path", config.STORAGE_PATH)
    config.STORAGE_BASE_URL = storage_config.get("base_url", config.STORAGE_BASE_URL)
    config.STORAGE_ALLOCATED_GB = int(
        storage_config.get("allocated_space_gb", config.STORAGE_ALLOCATED_GB)
    )

    if storage_config["provider"] == "s3":
        config.S3_BUCKET_NAME = storage_config.get("bucket_name")
        config.S3_REGION = storage_config.get("region", "us-east-1")
        config.S3_ACCESS_KEY = storage_config.get("access_key")
        config.S3_SECRET_KEY = storage_config.get("secret_key")
        config.S3_ENDPOINT_URL = storage_config.get("endpoint_url")

    config_handler.write_config(config=config.export_toml())


async def _exercise_storage_backend(storage_config: dict) -> tuple[bool, str]:
    """Run upload/read/delete smoke checks against a storage backend."""
    backend = (
        LocalStorageBackend(storage_config)
        if storage_config["provider"] == "local"
        else S3StorageBackend(storage_config)
    )
    test_path = "cli-healthcheck/test.txt"
    test_content = b"pufferblow storage healthcheck"

    await backend.upload_file(test_content, test_path)
    downloaded = await backend.download_file(test_path)
    if downloaded != test_content:
        return (False, "content mismatch during read verification")
    await backend.delete_file(test_path)
    return (True, "storage backend test passed")


def _config_to_storage_dict(config: Config) -> dict:
    """Map config model values to storage config dict."""
    return {
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


def setup_storage_command() -> None:
    """Interactive storage backend setup wizard."""
    provider_choice = _prompt_provider()
    if provider_choice == "4":
        console.print("[dim]Storage setup cancelled.[/dim]")
        return

    if provider_choice == "1":
        storage_config = _prompt_local_config()
    elif provider_choice == "2":
        storage_config = _prompt_s3_config(is_aws=True)
    else:
        storage_config = _prompt_s3_config(is_aws=False)

    if Confirm.ask("Run storage backend test now?", default=True):
        try:
            ok, message = asyncio.run(_exercise_storage_backend(storage_config))
        except Exception as exc:
            ok, message = False, str(exc)
        if not ok and not Confirm.ask(
            f"Storage test failed ({message}). Save config anyway?",
            default=False,
        ):
            return
        if ok:
            console.print(f"[green]{message}[/green]")

    _save_storage_config(storage_config)
    console.print("[green]Storage configuration saved.[/green]")


def test_storage_command() -> None:
    """Test the currently configured storage backend."""
    config_handler = ConfigHandler()
    if not config_handler.check_config():
        logger.error("No config file found. Run 'pufferblow storage setup' first.")
        raise typer.Exit(code=1)

    config = Config(config=config_handler.load_config())
    storage_config = _config_to_storage_dict(config)

    try:
        ok, message = asyncio.run(_exercise_storage_backend(storage_config))
    except Exception as exc:
        ok, message = False, str(exc)

    if ok:
        console.print(f"[green]{message}[/green]")
        return

    console.print(f"[red]Storage test failed: {message}[/red]")
    raise typer.Exit(code=1)


def migrate_storage_command(
    source_provider: str = typer.Option(
        ..., "--source-provider", help="Source provider ('local' or 's3')."
    ),
    target_provider: str = typer.Option(
        ..., "--target-provider", help="Target provider ('local' or 's3')."
    ),
    batch_size: int = typer.Option(
        10, "--batch-size", help="How many files to migrate per batch."
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Analyze only, do not migrate files."
    ),
) -> None:
    """Migrate files between configured storage backends."""
    if source_provider not in {"local", "s3"} or target_provider not in {"local", "s3"}:
        logger.error("source/target provider must be either 'local' or 's3'.")
        raise typer.Exit(code=1)

    config_handler = ConfigHandler()
    if not config_handler.check_config():
        logger.error("No config file found. Run 'pufferblow setup' first.")
        raise typer.Exit(code=1)

    config = Config(config=config_handler.load_config())
    api_initializer.load_objects()

    try:
        from scripts.migrate_storage import StorageMigrator
    except ImportError as exc:
        logger.error("Storage migrator script is unavailable: {error}", error=str(exc))
        raise typer.Exit(code=1)

    source_config = _config_to_storage_dict(config)
    source_config["provider"] = source_provider
    target_config = _config_to_storage_dict(config)
    target_config["provider"] = target_provider

    migrator = StorageMigrator(
        source_config=source_config,
        target_config=target_config,
        database_handler=api_initializer.database_handler,
    )
    stats = asyncio.run(migrator.migrate_all_files(batch_size=batch_size, dry_run=dry_run))

    console.print("[bold]Migration results[/bold]")
    console.print(f"total_files={stats['total_files']}")
    console.print(f"migrated_files={stats['migrated_files']}")
    console.print(f"failed_files={stats['failed_files']}")
    console.print(f"skipped_files={stats['skipped_files']}")
    console.print(f"migrated_size_gb={stats['migrated_size'] / (1024**3):.2f}")

