"""
Storage Manager for Pufferblow

Manages different storage backends and provides unified file operations.
"""

import base64
import hashlib
import io
import os
import uuid
from datetime import datetime, timezone
from typing import Any

import magic  # python-magic for MIME detection
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import HTTPException, UploadFile
from loguru import logger
from PIL import Image
from sqlalchemy import update

from pufferblow.api.database.database_handler import DatabaseHandler
from pufferblow.api.database.tables.file_objects import FileObjects

from .local_storage import LocalStorageBackend
from .path_utils import normalize_storage_relative_path
from .s3_storage import S3StorageBackend
from .storage_backend import StorageBackend


class StorageManager:
    """Unified storage manager for different backends"""

    SSE_MAGIC = b"PBSE1"
    SSE_NONCE_SIZE = 12
    SSE_KEY_SIZE = 32  # AES-256 key length

    def __init__(
        self, storage_config: dict[str, Any], database_handler: DatabaseHandler
    ):
        """Initialize the instance."""
        self.database_handler = database_handler
        self.config = storage_config
        self.sse_enabled = bool(self.config.get("sse_enabled", False))
        self.sse_key = self._load_sse_key() if self.sse_enabled else None

        self.backend = self._create_backend()
        self.mime_detector = magic.Magic(mime=True)

        # File type validation - defaults, updated from server settings
        self.IMAGE_EXTENSIONS = ["png", "jpg", "jpeg", "gif", "webp"]
        self.STICKER_EXTENSIONS = ["png", "gif"]
        self.GIF_EXTENSIONS = ["gif"]
        self.VIDEO_EXTENSIONS = ["mp4", "webm", "mov", "avi"]
        self.AUDIO_EXTENSIONS = ["mp3", "wav", "ogg", "m4a", "aac", "flac", "opus"]
        self.DOCUMENT_EXTENSIONS = ["pdf", "doc", "docx", "txt", "zip"]
        self.MAX_IMAGE_SIZE_MB = 5
        self.MAX_VIDEO_SIZE_MB = 50
        self.MAX_STICKER_SIZE_MB = 5
        self.MAX_GIF_SIZE_MB = 10
        self.MAX_AUDIO_SIZE_MB = 10
        self.MAX_DOCUMENT_SIZE_MB = 10
        self.MAX_TOTAL_ATTACHMENT_SIZE_MB = 50

    def _load_sse_key(self) -> bytes | None:
        """Load and normalize SSE key material to a 32-byte AES key."""
        configured_key = self.config.get("sse_key")
        if not configured_key:
            logger.warning(
                "Storage SSE requested but no key provided. Disabling storage SSE."
            )
            self.sse_enabled = False
            return None

        if isinstance(configured_key, bytes):
            key_bytes = configured_key
        else:
            key_text = str(configured_key).strip()
            if key_text.startswith("base64:"):
                try:
                    key_bytes = base64.b64decode(key_text[7:].encode("utf-8"))
                except Exception:
                    logger.warning(
                        "Invalid base64 SSE key format. Falling back to SHA-256 derivation."
                    )
                    key_bytes = hashlib.sha256(key_text.encode("utf-8")).digest()
            else:
                key_bytes = hashlib.sha256(key_text.encode("utf-8")).digest()

        if len(key_bytes) != self.SSE_KEY_SIZE:
            key_bytes = hashlib.sha256(key_bytes).digest()

        logger.info("Storage SSE enabled with AES-256 envelope encryption.")
        return key_bytes

    def _encrypt_for_storage(self, plain_content: bytes) -> bytes:
        """Encrypt file content before writing to storage backend."""
        if not self.sse_enabled or not self.sse_key:
            return plain_content

        nonce = os.urandom(self.SSE_NONCE_SIZE)
        ciphertext = AESGCM(self.sse_key).encrypt(nonce, plain_content, None)
        return self.SSE_MAGIC + nonce + ciphertext

    def _decrypt_from_storage(self, stored_content: bytes) -> bytes:
        """Decrypt previously encrypted storage content."""
        if not self.sse_enabled or not self.sse_key:
            return stored_content

        if not stored_content.startswith(self.SSE_MAGIC):
            raise HTTPException(
                status_code=500,
                detail="Storage object is not encrypted with the configured SSE envelope",
            )

        prefix_len = len(self.SSE_MAGIC)
        if len(stored_content) <= prefix_len + self.SSE_NONCE_SIZE:
            raise HTTPException(status_code=500, detail="Corrupted encrypted file")

        nonce_start = prefix_len
        nonce_end = nonce_start + self.SSE_NONCE_SIZE
        nonce = stored_content[nonce_start:nonce_end]
        ciphertext = stored_content[nonce_end:]

        try:
            return AESGCM(self.sse_key).decrypt(nonce, ciphertext, None)
        except Exception:
            raise HTTPException(
                status_code=500, detail="Failed to decrypt encrypted storage object"
            )

    async def read_file_content(self, file_path: str) -> bytes:
        """Read and transparently decrypt storage content."""
        normalized_path = normalize_storage_relative_path(file_path)
        stored_content = await self.backend.download_file(normalized_path)
        return self._decrypt_from_storage(stored_content)

    def _create_backend(self) -> StorageBackend:
        """Create storage backend based on configuration."""
        provider = self.config.get("provider", "local")

        if provider == "local":
            return LocalStorageBackend(self.config)
        elif provider == "s3":
            return S3StorageBackend(self.config)
        else:
            raise ValueError(f"Unsupported storage provider: {provider}")

    def compute_file_hash(self, content: bytes) -> str:
        """Compute SHA-256 hash of file content."""
        return hashlib.sha256(content).hexdigest()

    def categorize_file(self, filename: str, mime_type: str) -> str:
        """Categorize file based on MIME type and return subdirectory."""
        extension = filename.split(".")[-1].lower() if "." in filename else ""

        if mime_type.startswith("image/"):
            if extension in self.GIF_EXTENSIONS:
                return "gifs"
            elif extension in self.STICKER_EXTENSIONS and "_sticker" in filename.lower():
                return "stickers"
            elif "_avatar" in filename.lower():
                return "avatars"
            elif "_banner" in filename.lower():
                return "banners"
            else:
                return "images"
        elif mime_type.startswith("video/"):
            return "videos"
        elif mime_type.startswith("audio/"):
            return "audio"
        elif mime_type in [
            "application/pdf",
            "application/msword",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "text/plain",
            "application/zip",
        ]:
            return "documents"
        elif extension in ["json", "xml", "yaml", "yml"]:
            return "config"
        else:
            return "files"

    def find_duplicate_by_hash(self, file_hash: str) -> tuple[str, str] | None:
        """Resolve an existing stored file by content hash. Returns (relative_path, public_url)."""
        file_object = self.database_handler.get_file_object_by_hash(file_hash)
        if not file_object:
            return None

        try:
            relative_path = normalize_storage_relative_path(file_object.file_path)
        except ValueError:
            return None

        storage_base_url = str(self.config.get("base_url", "/storage")).rstrip("/")
        return relative_path, f"{storage_base_url}/{file_hash}"

    def _register_storage_reference(
        self,
        *,
        file_hash: str,
        user_id: str,
        reference_type: str,
        reference_id: str | None = None,
    ) -> None:
        """Create a reference row, keep ref_count in sync, and update last_referenced."""
        self.database_handler.increment_file_reference_count(file_hash)

        self.database_handler.create_file_reference(
            reference_id=reference_id or f"{reference_type}_{uuid.uuid4()}",
            file_hash=file_hash,
            reference_type=reference_type,
            reference_entity_id=user_id,
        )

        # Update last_referenced timestamp
        try:
            database_uri = str(self.database_handler.database_engine.url)
            if not database_uri.startswith("sqlite://"):
                with self.database_handler.database_session() as session:
                    session.execute(
                        update(FileObjects)
                        .where(FileObjects.file_hash == file_hash)
                        .values(last_referenced=datetime.now(timezone.utc))
                    )
                    session.commit()
        except Exception as exc:
            logger.warning(f"Failed to update last_referenced for {file_hash}: {exc}")

    def _size_limit_for_category(self, category: str) -> tuple[int, list[str]]:
        """Return (max_size_mb, allowed_extensions) for a storage category."""
        if category in ("images", "avatars", "banners"):
            return self.MAX_IMAGE_SIZE_MB, self.IMAGE_EXTENSIONS
        elif category == "gifs":
            return self.MAX_GIF_SIZE_MB, self.GIF_EXTENSIONS
        elif category == "stickers":
            return self.MAX_STICKER_SIZE_MB, self.STICKER_EXTENSIONS
        elif category == "videos":
            return self.MAX_VIDEO_SIZE_MB, self.VIDEO_EXTENSIONS
        elif category == "audio":
            return self.MAX_AUDIO_SIZE_MB, self.AUDIO_EXTENSIONS
        elif category == "documents":
            return self.MAX_DOCUMENT_SIZE_MB, self.DOCUMENT_EXTENSIONS
        else:
            return 10, ["*"]

    def update_server_limits(self):
        """Update file size limits from server settings."""
        try:
            server_settings = self.database_handler.get_server_settings()
            if server_settings:
                self.MAX_IMAGE_SIZE_MB = server_settings.max_image_size or 5
                self.MAX_VIDEO_SIZE_MB = server_settings.max_video_size or 50
                self.MAX_STICKER_SIZE_MB = server_settings.max_sticker_size or 5
                self.MAX_GIF_SIZE_MB = server_settings.max_gif_size or 10
                self.MAX_DOCUMENT_SIZE_MB = (
                    server_settings.max_message_length // 1000 or 10
                )
                self.MAX_AUDIO_SIZE_MB = self.MAX_DOCUMENT_SIZE_MB
                self.IMAGE_EXTENSIONS = server_settings.allowed_images_extensions or [
                    "png", "jpg", "jpeg", "gif", "webp",
                ]
                self.STICKER_EXTENSIONS = (
                    server_settings.allowed_stickers_extensions or ["png", "gif"]
                )
                self.GIF_EXTENSIONS = server_settings.allowed_gif_extensions or ["gif"]
                self.VIDEO_EXTENSIONS = server_settings.allowed_videos_extensions or [
                    "mp4", "webm",
                ]
                self.AUDIO_EXTENSIONS = self.AUDIO_EXTENSIONS or [
                    "mp3", "wav", "ogg", "m4a", "aac", "flac", "opus",
                ]
                self.DOCUMENT_EXTENSIONS = server_settings.allowed_doc_extensions or [
                    "pdf", "doc", "docx", "txt", "zip",
                ]
        except Exception:
            pass  # Use defaults

    async def upload_file(
        self,
        file: UploadFile,
        user_id: str,
        reference_type: str,
        force_category: str | None = None,
        check_duplicates: bool = True,
    ) -> tuple[str, bool, str, str, int]:
        """
        Validate and store an uploaded file.

        Returns:
            (public_url, is_duplicate, original_filename, mime_type, file_size_bytes)
        """
        self.update_server_limits()

        # Read content exactly once
        content = file.file.read()
        filename = file.filename or "unknown"
        extension = filename.split(".")[-1].lower() if "." in filename else ""
        file_size = len(content)

        mime_type = self.mime_detector.from_buffer(content)
        if not mime_type:
            raise HTTPException(status_code=400, detail="Cannot determine file type")

        category = force_category if force_category else self.categorize_file(filename, mime_type)
        max_size_mb, allowed_extensions = self._size_limit_for_category(category)

        if file_size > max_size_mb * 1024 * 1024:
            raise HTTPException(
                status_code=400,
                detail=f"File size exceeds maximum of {max_size_mb}MB",
            )

        if "*" not in allowed_extensions and extension not in allowed_extensions:
            raise HTTPException(
                status_code=400,
                detail=f"File extension '{extension}' not allowed. Allowed: {', '.join(allowed_extensions)}",
            )

        # Validate image integrity using in-memory buffer (avoids corrupting file handle)
        if mime_type.startswith("image/") and extension in self.IMAGE_EXTENSIONS:
            try:
                img = Image.open(io.BytesIO(content))
                img.verify()
                # Re-open after verify() since verify() closes the PIL image
                img = Image.open(io.BytesIO(content))
                max_dimension = 2048
                if img.width > max_dimension or img.height > max_dimension:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Image dimensions too large. Max allowed: {max_dimension}x{max_dimension}",
                    )
            except HTTPException:
                raise
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid image file")

        # Deduplication check
        file_hash = self.compute_file_hash(content)
        if check_duplicates:
            duplicate = self.find_duplicate_by_hash(file_hash)
            if duplicate:
                existing_path, existing_url = duplicate
                if await self.backend.file_exists(existing_path):
                    self._register_storage_reference(
                        file_hash=file_hash,
                        user_id=user_id,
                        reference_type=reference_type,
                    )
                    # Retrieve stored metadata for the duplicate
                    file_obj = self.database_handler.get_file_object_by_hash(file_hash)
                    dup_filename = file_obj.filename if file_obj else filename
                    dup_mime = file_obj.mime_type if file_obj else mime_type
                    dup_size = file_obj.file_size if file_obj else file_size
                    return existing_url, True, dup_filename, dup_mime, dup_size

        # Generate unique storage path
        file_id = str(uuid.uuid4())
        new_filename = f"{file_id}.{extension}" if extension else file_id
        storage_path = normalize_storage_relative_path(f"{category}/{new_filename}")

        stored_content = self._encrypt_for_storage(content)
        _ = await self.backend.upload_file(stored_content, storage_path)

        # Register in database
        self.database_handler.create_file_object(
            file_hash=file_hash,
            ref_count=1,
            file_path=storage_path,
            filename=filename,
            file_size=file_size,
            mime_type=mime_type,
            verification_status="verified",
        )
        self.database_handler.create_file_reference(
            reference_id=f"{reference_type}_{file_id}",
            file_hash=file_hash,
            reference_type=reference_type,
            reference_entity_id=user_id,
        )

        # Trigger async image optimization for avatars, banners, and images
        if category in ("avatars", "banners", "images") and mime_type.startswith("image/"):
            try:
                from pufferblow.core.bootstrap import api_initializer

                if (
                    hasattr(api_initializer, "background_tasks_manager")
                    and api_initializer.background_tasks_manager
                ):
                    await api_initializer.background_tasks_manager.run_task(
                        f"optimize_image_{file_id}",
                        task_func=api_initializer.background_tasks_manager.optimize_image,
                        file_path=storage_path,
                        file_hash=file_hash,
                        mime_type=mime_type,
                        category=category,
                    )
            except Exception as exc:
                logger.warning(f"Failed to trigger image optimization for {storage_path}: {exc}")

        storage_base_url = str(self.config.get("base_url", "/storage")).rstrip("/")
        public_url = f"{storage_base_url}/{file_hash}"
        return public_url, False, filename, mime_type, file_size

    async def delete_file(self, file_path: str) -> bool:
        """Delete file from storage."""
        normalized_path = normalize_storage_relative_path(file_path)
        return await self.backend.delete_file(normalized_path)

    async def get_file_info(self, file_path: str) -> dict[str, Any] | None:
        """Get file information."""
        normalized_path = normalize_storage_relative_path(file_path)
        if not await self.backend.file_exists(normalized_path):
            return None
        return {"path": normalized_path, "exists": True}

    async def cleanup_orphaned_files(self, valid_files: list[str]):
        """Clean up orphaned files."""
        if hasattr(self.backend, "cleanup_orphaned_files"):
            return await self.backend.cleanup_orphaned_files(valid_files)
        return 0

    async def get_storage_info(self) -> dict[str, Any]:
        """Get storage backend information."""
        return await self.backend.get_storage_info()
