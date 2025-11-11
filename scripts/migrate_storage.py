#!/usr/bin/env python3
"""
Storage Migration Script for Pufferblow

Migrates files between different storage backends (local to S3, S3 to local, etc.)
"""

import asyncio
import sys
import os
from pathlib import Path
from typing import Dict, Any, List, Optional
import shutil
import logging

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from pufferblow.api_initializer import APIInitializer
from pufferblow.api.storage.storage_backend import StorageBackend
from pufferblow.api.storage.local_storage import LocalStorageBackend
from pufferblow.api.storage.s3_storage import S3StorageBackend
from loguru import logger


class StorageMigrator:
    """Handles migration between storage backends"""

    def __init__(self, source_config: Dict[str, Any], target_config: Dict[str, Any],
                 database_handler):
        self.source_config = source_config
        self.target_config = target_config
        self.database_handler = database_handler

        self.source_backend = self._create_backend(source_config)
        self.target_backend = self._create_backend(target_config)

        # Migration stats
        self.stats = {
            'total_files': 0,
            'migrated_files': 0,
            'failed_files': 0,
            'skipped_files': 0,
            'total_size': 0,
            'migrated_size': 0
        }

    def _create_backend(self, config: Dict[str, Any]) -> StorageBackend:
        """Create storage backend from config"""
        provider = config.get("provider", "local")

        if provider == "local":
            return LocalStorageBackend(config)
        elif provider == "s3":
            return S3StorageBackend(config)
        else:
            raise ValueError(f"Unsupported storage provider: {provider}")

    async def migrate_all_files(self, batch_size: int = 10, dry_run: bool = False) -> Dict[str, Any]:
        """
        Migrate all files from source to target backend

        Args:
            batch_size: Number of files to migrate in each batch
            dry_run: If True, only analyze without migrating

        Returns:
            Migration statistics
        """
        logger.info("Starting storage migration...")
        logger.info(f"Source: {self.source_config.get('provider', 'unknown')}")
        logger.info(f"Target: {self.target_config.get('provider', 'unknown')}")
        logger.info(f"Dry run: {dry_run}")

        try:
            # Get all files from database
            all_files = await self._get_all_files_from_database()
            self.stats['total_files'] = len(all_files)

            logger.info(f"Found {len(all_files)} files to migrate")

            if dry_run:
                # Just analyze file sizes
                await self._analyze_files(all_files)
                logger.info("Dry run completed - no files migrated")
                return self.stats

            # Migrate files in batches
            for i in range(0, len(all_files), batch_size):
                batch = all_files[i:i + batch_size]
                await self._migrate_batch(batch)

                # Log progress
                progress = min(i + batch_size, len(all_files))
                logger.info(f"Migrated {progress}/{len(all_files)} files")

            # Update database references
            await self._update_database_references()

            logger.info("Migration completed successfully!")
            logger.info(f"Stats: {self.stats}")

            return self.stats

        except Exception as e:
            logger.error(f"Migration failed: {str(e)}")
            raise

    async def _get_all_files_from_database(self) -> List[Dict[str, Any]]:
        """Get all file records from database"""
        try:
            with self.database_handler.database_session() as session:
                from pufferblow.api.database.tables.file_objects import FileObjects

                # Get all files from file_objects table
                files = session.query(FileObjects).all()

                file_list = []
                for file_obj in files:
                    file_list.append({
                        'file_hash': file_obj.file_hash,
                        'file_path': file_obj.file_path,
                        'file_size': file_obj.file_size,
                        'mime_type': file_obj.mime_type
                    })

                return file_list

        except Exception as e:
            logger.error(f"Failed to get files from database: {str(e)}")
            return []

    async def _analyze_files(self, files: List[Dict[str, Any]]):
        """Analyze files for dry run"""
        for file_info in files:
            self.stats['total_size'] += file_info.get('file_size', 0)

        logger.info(f"Total files: {len(files)}")
        logger.info(f"Total size: {self.stats['total_size'] / (1024**3):.2f} GB")

    async def _migrate_batch(self, batch: List[Dict[str, Any]]):
        """Migrate a batch of files"""
        for file_info in batch:
            try:
                file_path = file_info['file_path']
                file_size = file_info.get('file_size', 0)

                # Check if file exists in source
                if not await self.source_backend.file_exists(file_path):
                    logger.warning(f"Source file not found: {file_path}")
                    self.stats['skipped_files'] += 1
                    continue

                # Download from source
                content = await self.source_backend.download_file(file_path)

                # Verify content size
                if len(content) != file_size:
                    logger.warning(f"Size mismatch for {file_path}: expected {file_size}, got {len(content)}")

                # Upload to target
                await self.target_backend.upload_file(content, file_path)

                # Update stats
                self.stats['migrated_files'] += 1
                self.stats['migrated_size'] += len(content)

                logger.debug(f"Migrated: {file_path}")

            except Exception as e:
                logger.error(f"Failed to migrate {file_info.get('file_path', 'unknown')}: {str(e)}")
                self.stats['failed_files'] += 1

    async def _update_database_references(self):
        """Update database to reflect new storage backend"""
        # This is a simplified implementation
        # In a production system, you might want to update file URLs or add migration metadata
        logger.info("Database references updated (no changes needed for current implementation)")


async def main():
    """Main migration function"""
    import argparse

    parser = argparse.ArgumentParser(description="Migrate Pufferblow storage backend")
    parser.add_argument("--source-provider", required=True,
                       choices=["local", "s3"], help="Source storage provider")
    parser.add_argument("--target-provider", required=True,
                       choices=["local", "s3"], help="Target storage provider")
    parser.add_argument("--source-path", help="Source storage path (for local)")
    parser.add_argument("--target-path", help="Target storage path (for local)")
    parser.add_argument("--source-bucket", help="Source S3 bucket name")
    parser.add_argument("--target-bucket", help="Target S3 bucket name")
    parser.add_argument("--source-region", default="us-east-1", help="Source S3 region")
    parser.add_argument("--target-region", default="us-east-1", help="Target S3 region")
    parser.add_argument("--batch-size", type=int, default=10, help="Batch size for migration")
    parser.add_argument("--dry-run", action="store_true", help="Analyze without migrating")
    parser.add_argument("--config", help="Path to config file")

    args = parser.parse_args()

    # Initialize API (this will load config and database)
    api_init = APIInitializer()

    # Override config if specified
    if args.config:
        os.environ['PUFFERBLOW_CONFIG'] = args.config

    api_init.load_objects()

    # Create source config
    source_config = {
        "provider": args.source_provider,
        "storage_path": args.source_path or api_init.config.STORAGE_PATH,
        "base_url": api_init.config.STORAGE_BASE_URL,
        "bucket_name": args.source_bucket or api_init.config.S3_BUCKET_NAME,
        "region": args.source_region or api_init.config.S3_REGION,
        "access_key": api_init.config.S3_ACCESS_KEY,
        "secret_key": api_init.config.S3_SECRET_KEY,
        "endpoint_url": api_init.config.S3_ENDPOINT_URL
    }

    # Create target config
    target_config = {
        "provider": args.target_provider,
        "storage_path": args.target_path or api_init.config.STORAGE_PATH,
        "base_url": api_init.config.STORAGE_BASE_URL,
        "bucket_name": args.target_bucket or api_init.config.S3_BUCKET_NAME,
        "region": args.target_region or api_init.config.S3_REGION,
        "access_key": api_init.config.S3_ACCESS_KEY,
        "secret_key": api_init.config.S3_SECRET_KEY,
        "endpoint_url": api_init.config.S3_ENDPOINT_URL
    }

    # Create migrator
    migrator = StorageMigrator(
        source_config=source_config,
        target_config=target_config,
        database_handler=api_init.database_handler
    )

    # Run migration
    stats = await migrator.migrate_all_files(
        batch_size=args.batch_size,
        dry_run=args.dry_run
    )

    # Print final stats
    print("\nMigration completed!")
    print(f"Total files: {stats['total_files']}")
    print(f"Migrated: {stats['migrated_files']}")
    print(f"Failed: {stats['failed_files']}")
    print(f"Skipped: {stats['skipped_files']}")
    print(f"Total size: {stats['total_size'] / (1024**3):.2f} GB")
    print(f"Migrated size: {stats['migrated_size'] / (1024**3):.2f} GB")


if __name__ == "__main__":
    asyncio.run(main())
