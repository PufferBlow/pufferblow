#!/usr/bin/env python3
"""
Storage migration script for Pufferblow.

Supports:
- local -> local / s3
- s3 -> local / s3
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Any

from sqlalchemy import select

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from loguru import logger

from pufferblow.api.database.tables.file_objects import FileObjects
from pufferblow.api.storage.local_storage import LocalStorageBackend
from pufferblow.api.storage.path_utils import normalize_storage_relative_path
from pufferblow.api.storage.s3_storage import S3StorageBackend
from pufferblow.api.storage.storage_backend import StorageBackend
from pufferblow.core.bootstrap import APIInitializer


class StorageMigrator:
    """Handles migration between storage backends."""

    def __init__(
        self,
        source_config: dict[str, Any],
        target_config: dict[str, Any],
        database_handler,
    ):
        self.source_config = source_config
        self.target_config = target_config
        self.database_handler = database_handler

        self.source_backend = self._create_backend(source_config)
        self.target_backend = self._create_backend(target_config)

        self.stats = {
            "total_files": 0,
            "migrated_files": 0,
            "failed_files": 0,
            "skipped_files": 0,
            "total_size": 0,
            "migrated_size": 0,
        }

    def _create_backend(self, config: dict[str, Any]) -> StorageBackend:
        """Create storage backend from config."""
        provider = config.get("provider", "local")
        if provider == "local":
            return LocalStorageBackend(config)
        if provider == "s3":
            return S3StorageBackend(config)
        raise ValueError(f"Unsupported storage provider: {provider}")

    async def migrate_all_files(
        self, batch_size: int = 10, dry_run: bool = False
    ) -> dict[str, Any]:
        """Migrate all files recorded in file_objects."""
        logger.info("Starting storage migration...")
        logger.info(f"Source: {self.source_config.get('provider', 'unknown')}")
        logger.info(f"Target: {self.target_config.get('provider', 'unknown')}")
        logger.info(f"Dry run: {dry_run}")

        all_files = await self._get_all_files_from_database()
        self.stats["total_files"] = len(all_files)
        logger.info(f"Found {len(all_files)} files to migrate")

        if dry_run:
            await self._analyze_files(all_files)
            logger.info("Dry run completed - no files migrated")
            return self.stats

        for index in range(0, len(all_files), batch_size):
            batch = all_files[index : index + batch_size]
            await self._migrate_batch(batch)
            progress = min(index + batch_size, len(all_files))
            logger.info(f"Migrated {progress}/{len(all_files)} files")

        logger.info(f"Migration completed successfully with stats: {self.stats}")
        return self.stats

    async def _get_all_files_from_database(self) -> list[dict[str, Any]]:
        """Get tracked file records from file_objects."""
        try:
            with self.database_handler.database_session() as session:
                files = session.execute(select(FileObjects)).scalars().all()
            return [
                {
                    "file_hash": file_obj.file_hash,
                    "file_path": file_obj.file_path,
                    "file_size": file_obj.file_size,
                    "mime_type": file_obj.mime_type,
                }
                for file_obj in files
            ]
        except Exception as exc:
            logger.error(f"Failed to get files from database: {exc}")
            return []

    async def _analyze_files(self, files: list[dict[str, Any]]) -> None:
        """Analyze size impact for a dry run."""
        for file_info in files:
            self.stats["total_size"] += file_info.get("file_size", 0)

        logger.info(f"Total files: {len(files)}")
        logger.info(f"Total size: {self.stats['total_size'] / (1024**3):.2f} GB")

    async def _migrate_batch(self, batch: list[dict[str, Any]]) -> None:
        """Migrate a batch of indexed storage files."""
        for file_info in batch:
            try:
                file_path = normalize_storage_relative_path(file_info["file_path"])
                file_size = file_info.get("file_size", 0)

                if not await self.source_backend.file_exists(file_path):
                    logger.warning(f"Source file not found: {file_path}")
                    self.stats["skipped_files"] += 1
                    continue

                content = await self.source_backend.download_file(file_path)
                if len(content) != file_size:
                    logger.warning(
                        f"Size mismatch for {file_path}: expected {file_size}, got {len(content)}"
                    )

                await self.target_backend.upload_file(content, file_path)
                self.stats["migrated_files"] += 1
                self.stats["migrated_size"] += len(content)
            except Exception as exc:
                logger.error(
                    f"Failed to migrate {file_info.get('file_path', 'unknown')}: {exc}"
                )
                self.stats["failed_files"] += 1


async def main() -> None:
    """Main migration function."""
    import argparse

    parser = argparse.ArgumentParser(description="Migrate Pufferblow storage backend")
    parser.add_argument(
        "--source-provider",
        required=True,
        choices=["local", "s3"],
        help="Source storage provider",
    )
    parser.add_argument(
        "--target-provider",
        required=True,
        choices=["local", "s3"],
        help="Target storage provider",
    )
    parser.add_argument("--source-path", help="Source storage path (for local)")
    parser.add_argument("--target-path", help="Target storage path (for local)")
    parser.add_argument("--source-bucket", help="Source S3 bucket name")
    parser.add_argument("--target-bucket", help="Target S3 bucket name")
    parser.add_argument("--source-region", default="us-east-1", help="Source S3 region")
    parser.add_argument("--target-region", default="us-east-1", help="Target S3 region")
    parser.add_argument(
        "--batch-size", type=int, default=10, help="Batch size for migration"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Analyze without migrating"
    )
    parser.add_argument("--config", help="Path to config file")

    args = parser.parse_args()

    if args.config:
        os.environ["PUFFERBLOW_CONFIG"] = args.config

    api_init = APIInitializer()
    api_init.load_objects()

    source_config = {
        "provider": args.source_provider,
        "storage_path": args.source_path or api_init.config.STORAGE_PATH,
        "base_url": api_init.config.STORAGE_BASE_URL,
        "allocated_space_gb": api_init.config.STORAGE_ALLOCATED_GB,
        "api_host": api_init.config.API_HOST,
        "api_port": api_init.config.API_PORT,
        "bucket_name": args.source_bucket or api_init.config.S3_BUCKET_NAME,
        "region": args.source_region or api_init.config.S3_REGION,
        "access_key": api_init.config.S3_ACCESS_KEY,
        "secret_key": api_init.config.S3_SECRET_KEY,
        "endpoint_url": api_init.config.S3_ENDPOINT_URL,
    }

    target_config = {
        "provider": args.target_provider,
        "storage_path": args.target_path or api_init.config.STORAGE_PATH,
        "base_url": api_init.config.STORAGE_BASE_URL,
        "allocated_space_gb": api_init.config.STORAGE_ALLOCATED_GB,
        "api_host": api_init.config.API_HOST,
        "api_port": api_init.config.API_PORT,
        "bucket_name": args.target_bucket or api_init.config.S3_BUCKET_NAME,
        "region": args.target_region or api_init.config.S3_REGION,
        "access_key": api_init.config.S3_ACCESS_KEY,
        "secret_key": api_init.config.S3_SECRET_KEY,
        "endpoint_url": api_init.config.S3_ENDPOINT_URL,
    }

    migrator = StorageMigrator(
        source_config=source_config,
        target_config=target_config,
        database_handler=api_init.database_handler,
    )

    stats = await migrator.migrate_all_files(
        batch_size=args.batch_size,
        dry_run=args.dry_run,
    )

    print("\nMigration completed!")
    print(f"Total files: {stats['total_files']}")
    print(f"Migrated: {stats['migrated_files']}")
    print(f"Failed: {stats['failed_files']}")
    print(f"Skipped: {stats['skipped_files']}")
    print(f"Total size: {stats['total_size'] / (1024**3):.2f} GB")
    print(f"Migrated size: {stats['migrated_size'] / (1024**3):.2f} GB")


if __name__ == "__main__":
    asyncio.run(main())
