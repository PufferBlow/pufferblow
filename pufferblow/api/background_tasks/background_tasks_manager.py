import asyncio
import io
import logging
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from loguru import logger
from PIL import Image

from pufferblow.api.background_tasks.analytics_mixin import BackgroundTaskAnalyticsMixin
from pufferblow.api.background_tasks.scheduler_mixin import BackgroundTaskSchedulerMixin
from pufferblow.api.database.database_handler import DatabaseHandler

try:
    from pufferblow.api.storage.storage_manager import StorageManager
except ImportError:
    StorageManager = None
from pufferblow.api.database.tables.users import Users
from pufferblow.api.models.config_model import Config


class BackgroundTasksManager(BackgroundTaskSchedulerMixin, BackgroundTaskAnalyticsMixin):
    """Background task coordinator for scheduled maintenance and analytics."""

    def __init__(
        self,
        database_handler: DatabaseHandler,
        storage_manager: StorageManager,
        config: Config,
    ):
        """Initialize the instance."""
        self.database_handler = database_handler
        self.storage_manager = storage_manager
        self.config = config
        self.tasks: dict[str, dict[str, Any]] = {}
        self.executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="bg-task")
        self.running_tasks: dict[str, asyncio.Task] = {}
        self.task_stats: dict[str, dict[str, Any]] = {}
        self.chart_data: dict[str, dict[str, Any]] = {}
        self.logger = logging.getLogger(__name__)
        self._initialize_chart_data()

    async def cleanup_storage_orphaned_files(self):
        """Clean up orphaned files in storage."""
        logger.info("Starting storage cleanup task")

        try:
            if not self.storage_manager:
                logger.info("Storage manager not available, skipping cleanup task")
                return

            referenced_urls = await self._get_referenced_file_urls()
            all_categories = [
                "files",
                "images",
                "avatars",
                "banners",
                "gifs",
                "stickers",
                "videos",
                "audio",
                "documents",
                "config",
            ]

            total_deleted = 0
            for category in all_categories:
                directory_files = self._get_directory_files(category)
                subdir_deleted = await self.storage_manager.cleanup_orphaned_files(
                    directory_files, category
                )
                total_deleted += subdir_deleted or 0

            logger.info(
                f"Storage cleanup completed. Deleted {total_deleted} orphaned files from {len(all_categories)} categories"
            )
        except Exception as exc:
            logger.error(f"Storage cleanup failed: {str(exc)}")
            raise

    async def _get_referenced_file_urls(self) -> list[str]:
        """Get all file URLs referenced in the database."""
        try:
            referenced_urls = []
            with self.database_handler.database_session() as session:
                from sqlalchemy import select

                result = session.execute(select(Users.avatar, Users.banner))
                for avatar, banner in result:
                    if avatar:
                        referenced_urls.append(avatar)
                    if banner:
                        referenced_urls.append(banner)

            return referenced_urls
        except Exception as exc:
            logger.error(f"Failed to get referenced file URLs: {str(exc)}")
            return []

    def _get_directory_files(self, subdirectory: str) -> list[str]:
        """Get all file URLs in a storage subdirectory."""
        try:
            sub_dir = Path(self.config.STORAGE_PATH) / subdirectory
            if not sub_dir.exists():
                return []

            files = []
            for file_path in sub_dir.glob("*"):
                if file_path.is_file():
                    files.append(
                        f"{self.config.STORAGE_BASE_URL.rstrip('/')}/{subdirectory}/{file_path.name}"
                    )
            return files
        except Exception as exc:
            logger.error(f"Failed to get directory files for {subdirectory}: {str(exc)}")
            return []

    def cleanup_expired_auth_tokens(self):
        """Clean up expired authentication tokens."""
        logger.info("Starting auth token cleanup task")
        try:
            logger.info("Auth token cleanup completed (not yet implemented)")
        except Exception as exc:
            logger.error(f"Auth token cleanup failed: {str(exc)}")
            raise

    def expire_stale_pings(self) -> None:
        """Transition pings that are past their expiry time to 'timeout' status."""
        logger.info("Running stale ping expiry task")
        try:
            count = self.database_handler.expire_stale_pings()
            logger.info(f"Stale ping expiry complete | transitioned={count}")
        except Exception as exc:
            logger.error(f"Stale ping expiry task failed: {str(exc)}")
            raise

    def optimize_image(self, file_path: str, file_hash: str, mime_type: str, category: str):
        """Optimize uploaded images by converting them to AVIF format."""
        try:
            logger.info(
                f"Starting image optimization for {file_path} (category: {category})"
            )

            if mime_type in [
                "image/gif",
                "video/mp4",
                "video/webm",
                "video/mov",
                "video/avi",
            ]:
                logger.info(f"Skipping optimization for {mime_type} file: {file_path}")
                return

            supported_formats = ["image/png", "image/jpeg", "image/jpg", "image/webp"]
            if mime_type not in supported_formats:
                logger.info(
                    f"Skipping optimization for unsupported format {mime_type}: {file_path}"
                )
                return

            if not self.storage_manager:
                logger.error("Storage manager not available for image optimization")
                return

            if hasattr(self.storage_manager.backend, "storage_path"):
                full_file_path = Path(self.storage_manager.backend.storage_path) / file_path
            else:
                logger.error("Cannot determine file path for optimization")
                return

            if not full_file_path.exists():
                logger.error(f"File does not exist for optimization: {full_file_path}")
                return

            with open(full_file_path, "rb") as file_obj:
                original_data = file_obj.read()

            original_size = len(original_data)
            logger.info(f"Original file size: {original_size} bytes")

            try:
                with Image.open(full_file_path) as img:
                    if img.mode in ("RGBA", "LA", "P"):
                        background = Image.new("RGB", img.size, (255, 255, 255))
                        if img.mode == "P":
                            img = img.convert("RGBA")
                        background.paste(
                            img, mask=img.split()[-1] if img.mode == "RGBA" else None
                        )
                        img = background
                    elif img.mode != "RGB":
                        img = img.convert("RGB")

                    avif_buffer = io.BytesIO()
                    img.save(
                        avif_buffer,
                        format="AVIF",
                        quality=85,
                        optimize=True,
                        subsampling=0,
                    )

                    optimized_data = avif_buffer.getvalue()
                    optimized_size = len(optimized_data)
                    compression_ratio = (
                        (original_size - optimized_size) / original_size * 100
                    )
                    logger.info(
                        f"Optimized file size: {optimized_size} bytes ({compression_ratio:.1f}% reduction)"
                    )

                    if compression_ratio > 5:
                        original_name = full_file_path.stem
                        new_filename = f"{original_name}.avif"
                        new_file_path = full_file_path.parent / new_filename

                        with open(new_file_path, "wb") as file_obj:
                            file_obj.write(optimized_data)

                        full_file_path.unlink()
                        new_file_hash = self.storage_manager.compute_file_hash(optimized_data)
                        new_mime_type = "image/avif"
                        new_relative_path = f"{full_file_path.parent.name}/{new_filename}"

                        try:
                            self.database_handler.update_file_object(
                                old_file_hash=file_hash,
                                new_file_hash=new_file_hash,
                                new_file_path=new_relative_path,
                                new_file_size=optimized_size,
                                new_mime_type=new_mime_type,
                            )
                            self.database_handler.update_file_references(
                                old_file_hash=file_hash,
                                new_file_hash=new_file_hash,
                            )
                            logger.info(
                                f"Successfully optimized image: {file_path} -> {new_relative_path}"
                            )
                            logger.info(
                                f"Compression achieved: {compression_ratio:.1f}% ({original_size} -> {optimized_size} bytes)"
                            )
                        except Exception as db_error:
                            logger.error(
                                f"Failed to update database after optimization: {str(db_error)}"
                            )
                            new_file_path.unlink()
                            with open(full_file_path, "wb") as file_obj:
                                file_obj.write(original_data)
                            raise
                    else:
                        logger.info(
                            f"Optimization not beneficial (only {compression_ratio:.1f}% reduction), keeping original file"
                        )
            except Exception as img_error:
                logger.error(
                    f"Image processing failed for {file_path}: {str(img_error)}"
                )
                raise
        except Exception as exc:
            logger.error(f"Image optimization failed for {file_path}: {str(exc)}")
            raise

    async def create_database_backup(self) -> None:
        """Create a database backup file using pg_dump."""
        import os
        import subprocess
        from datetime import datetime
        from pathlib import Path

        backup_path = Path(getattr(self.config, "BACKUP_PATH", "~/.pufferblow/backups")).expanduser()
        backup_path.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"pufferblow_backup_{timestamp}.dump"
        filepath = backup_path / filename

        env = os.environ.copy()
        env["PGPASSWORD"] = str(getattr(self.config, "DATABASE_PASSWORD", ""))

        cmd = [
            "pg_dump",
            "-h", str(getattr(self.config, "DATABASE_HOST", "localhost")),
            "-p", str(getattr(self.config, "DATABASE_PORT", 5432)),
            "-U", str(getattr(self.config, "USERNAME", "postgres")),
            "-Fc",
            "-f", str(filepath),
            str(getattr(self.config, "DATABASE_NAME", "pufferblow")),
        ]

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            self.executor,
            lambda: __import__("subprocess").run(cmd, env=env, capture_output=True, text=True),
        )

        if result.returncode != 0:
            raise RuntimeError(f"pg_dump failed: {result.stderr.strip()}")

        max_files = int(getattr(self.config, "BACKUP_MAX_FILES", 7))
        backups = sorted(backup_path.glob("pufferblow_backup_*.dump"))
        while len(backups) > max_files:
            backups.pop(0).unlink(missing_ok=True)

        logger.info(f"Database backup created: {filepath}")

    async def mirror_database(self) -> None:
        """Mirror the database to a secondary PostgreSQL instance via pg_dump | psql."""
        import os

        mirror_dsn = getattr(self.config, "BACKUP_MIRROR_DSN", None)
        if not mirror_dsn:
            raise ValueError("BACKUP_MIRROR_DSN is not configured")

        env = os.environ.copy()
        env["PGPASSWORD"] = str(getattr(self.config, "DATABASE_PASSWORD", ""))

        dump_cmd = [
            "pg_dump",
            "-h", str(getattr(self.config, "DATABASE_HOST", "localhost")),
            "-p", str(getattr(self.config, "DATABASE_PORT", 5432)),
            "-U", str(getattr(self.config, "USERNAME", "postgres")),
            str(getattr(self.config, "DATABASE_NAME", "pufferblow")),
        ]
        restore_cmd = ["psql", mirror_dsn]

        loop = asyncio.get_event_loop()

        def _run_mirror():
            import subprocess
            dump_proc = subprocess.Popen(dump_cmd, stdout=subprocess.PIPE, env=env)
            restore_proc = subprocess.Popen(restore_cmd, stdin=dump_proc.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if dump_proc.stdout:
                dump_proc.stdout.close()
            _, stderr = restore_proc.communicate()
            dump_proc.wait()
            if restore_proc.returncode != 0:
                raise RuntimeError(f"Database mirror failed: {stderr.decode().strip()}")

        await loop.run_in_executor(self.executor, _run_mirror)
        logger.info("Database mirrored successfully")


@asynccontextmanager
async def lifespan_background_tasks():
    """Lifespan function to start background tasks."""
    from pufferblow.core.bootstrap import api_initializer

    if api_initializer.is_ready("background_tasks_manager"):
        scheduler_task = asyncio.create_task(
            api_initializer.background_tasks_manager.start_scheduler()
        )
        api_initializer._scheduler_task = scheduler_task

        yield

        if hasattr(api_initializer, "_scheduler_task"):
            api_initializer._scheduler_task.cancel()
            try:
                await api_initializer._scheduler_task
            except asyncio.CancelledError:
                pass
    else:
        yield
