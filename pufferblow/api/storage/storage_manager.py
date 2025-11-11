"""
Storage Manager for Pufferblow

Manages different storage backends and provides unified file operations.
"""

import uuid
import hashlib
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any
import magic  # python-magic for MIME detection
from PIL import Image
from fastapi import UploadFile, HTTPException
from loguru import logger

from .storage_backend import StorageBackend
from .local_storage import LocalStorageBackend
from .s3_storage import S3StorageBackend
from pufferblow.api.database.database_handler import DatabaseHandler


class StorageManager:
    """Unified storage manager for different backends"""

    def __init__(self, storage_config: Dict[str, Any], database_handler: DatabaseHandler):
        self.database_handler = database_handler
        self.config = storage_config

        # Initialize storage backend
        self.backend = self._create_backend()

        # MIME detector
        self.mime_detector = magic.Magic(mime=True)

        # File type validation - defaults, will be updated from server settings
        self.IMAGE_EXTENSIONS = ['png', 'jpg', 'jpeg', 'gif', 'webp']
        self.STICKER_EXTENSIONS = ['png', 'gif']
        self.GIF_EXTENSIONS = ['gif']
        self.VIDEO_EXTENSIONS = ['mp4', 'webm', 'mov', 'avi']
        self.DOCUMENT_EXTENSIONS = ['pdf', 'doc', 'docx', 'txt', 'zip']
        self.MAX_IMAGE_SIZE_MB = 5
        self.MAX_VIDEO_SIZE_MB = 50
        self.MAX_STICKER_SIZE_MB = 5
        self.MAX_GIF_SIZE_MB = 10
        self.MAX_DOCUMENT_SIZE_MB = 10

    def _create_backend(self) -> StorageBackend:
        """Create storage backend based on configuration"""
        provider = self.config.get("provider", "local")

        if provider == "local":
            return LocalStorageBackend(self.config)
        elif provider == "s3":
            return S3StorageBackend(self.config)
        else:
            raise ValueError(f"Unsupported storage provider: {provider}")

    def compute_file_hash(self, content: bytes) -> str:
        """Compute SHA-256 hash of file content"""
        return hashlib.sha256(content).hexdigest()

    def categorize_file(self, filename: str, mime_type: str) -> str:
        """Categorize file based on type and return subdirectory"""
        extension = filename.split('.')[-1].lower() if '.' in filename else ""

        if mime_type.startswith('image/'):
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
        elif mime_type.startswith('video/'):
            return "videos"
        elif mime_type.startswith('audio/'):
            return "audio"
        elif mime_type in ['application/pdf', 'application/msword',
                          'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                          'text/plain', 'application/zip']:
            return "documents"
        elif extension in ['json', 'xml', 'yaml', 'yml']:
            return "config"
        else:
            return "files"

    def find_duplicate_by_hash(self, file_hash: str, subdirectory: str) -> Optional[str]:
        """Check if file with same hash exists"""
        # This would require maintaining a hash index in the database
        # For now, return None (no duplicate checking)
        return None

    async def validate_and_save_categorized_file(
        self,
        file: UploadFile,
        user_id: str,
        check_duplicates: bool = True,
        force_category: Optional[str] = None
    ) -> Tuple[str, bool]:
        """Validate and save file with categorization"""
        content = file.file.read()
        filename = file.filename or "unknown"
        extension = filename.split('.')[-1].lower() if '.' in filename else ""

        mime_type = self.mime_detector.from_buffer(content)
        if not mime_type:
            raise HTTPException(status_code=400, detail="Cannot determine file type")

        category = force_category if force_category else self.categorize_file(filename, mime_type)

        # Set limits based on category
        if category == "images":
            max_size_mb = self.MAX_IMAGE_SIZE_MB
            allowed_extensions = self.IMAGE_EXTENSIONS
        elif category in ["avatars", "banners"]:
            max_size_mb = self.MAX_IMAGE_SIZE_MB
            allowed_extensions = self.IMAGE_EXTENSIONS
        elif category == "gifs":
            max_size_mb = self.MAX_GIF_SIZE_MB
            allowed_extensions = self.GIF_EXTENSIONS
        elif category == "stickers":
            max_size_mb = self.MAX_STICKER_SIZE_MB
            allowed_extensions = self.STICKER_EXTENSIONS
        elif category == "videos":
            max_size_mb = self.MAX_VIDEO_SIZE_MB
            allowed_extensions = self.VIDEO_EXTENSIONS
        elif category == "documents":
            max_size_mb = self.MAX_DOCUMENT_SIZE_MB
            allowed_extensions = self.DOCUMENT_EXTENSIONS
        else:
            max_size_mb = 10
            allowed_extensions = [extension] if extension else ['*']

        file.file.seek(0)
        return await self.validate_and_save_file(
            file=file,
            user_id=user_id,
            max_size_mb=max_size_mb,
            allowed_extensions=allowed_extensions,
            subdirectory=category,
            check_duplicates=check_duplicates
        )

    async def validate_and_save_file(
        self,
        file: UploadFile,
        user_id: str,
        max_size_mb: int,
        allowed_extensions: List[str],
        subdirectory: str = "files",
        check_duplicates: bool = True
    ) -> Tuple[str, bool]:
        """Validate and save file"""
        content = file.file.read()
        if len(content) > max_size_mb * 1024 * 1024:
            raise HTTPException(
                status_code=400,
                detail=f"File size exceeds maximum of {max_size_mb}MB"
            )

        mime_type = self.mime_detector.from_buffer(content)
        if not mime_type:
            raise HTTPException(status_code=400, detail="Cannot determine file type")

        filename = file.filename or "unknown"
        extension = filename.split('.')[-1].lower() if '.' in filename else ""
        if extension not in allowed_extensions and '*' not in allowed_extensions:
            raise HTTPException(
                status_code=400,
                detail=f"File extension '{extension}' not allowed. Allowed: {', '.join(allowed_extensions)}"
            )

        # Additional validation for images
        if extension in self.IMAGE_EXTENSIONS and mime_type.startswith('image/'):
            file.file.seek(0)
            try:
                image = Image.open(file.file)
                image.verify()
                max_dimension = 2048
                if image.size[0] > max_dimension or image.size[1] > max_dimension:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Image dimensions too large. Max allowed: {max_dimension}x{max_dimension}"
                    )
                file.file.seek(0)
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid image file")

        # Check for duplicates
        is_duplicate = False
        file_hash = ""
        if check_duplicates and len(content) > 0:
            file_hash = self.compute_file_hash(content)
            existing_url = self.find_duplicate_by_hash(file_hash, subdirectory)
            if existing_url:
                return existing_url, True

        # Generate unique filename
        file_id = str(uuid.uuid4())
        new_filename = f"{file_id}.{extension}"
        storage_path = f"{subdirectory}/{new_filename}"

        # Upload to storage backend
        url_path = await self.backend.upload_file(content, storage_path)

        # Register in database
        try:
            if not file_hash:
                file_hash = self.compute_file_hash(content)

            self.database_handler.create_file_object(
                file_hash=file_hash,
                ref_count=1,
                file_path=storage_path,
                file_size=len(content),
                mime_type=mime_type,
                verification_status="verified"
            )

            reference_id = f"storage_upload_{file_id}"
            self.database_handler.create_file_reference(
                reference_id=reference_id,
                file_hash=file_hash,
                reference_type="storage_upload",
                reference_entity_id=user_id
            )

        except Exception as e:
            # Log error but don't fail upload
            pass

        # Trigger image optimization for supported image types (avatars, banners, attachments)
        # This runs asynchronously as a background task
        if subdirectory in ['avatars', 'banners', 'images'] and mime_type.startswith('image/'):
            try:
                # Import here to avoid circular imports
                from pufferblow.api_initializer import api_initializer

                if hasattr(api_initializer, 'background_tasks_manager') and api_initializer.background_tasks_manager:
                    # Run image optimization as background task
                    await api_initializer.background_tasks_manager.run_task(
                        f"optimize_image_{file_id}",
                        task_func=api_initializer.background_tasks_manager.optimize_image,
                        file_path=storage_path,
                        file_hash=file_hash,
                        mime_type=mime_type,
                        category=subdirectory
                    )
                    logger.info(f"Triggered image optimization for {storage_path}")
                else:
                    logger.warning("Background tasks manager not available for image optimization")

            except Exception as e:
                # Don't fail the upload if optimization fails
                logger.warning(f"Failed to trigger image optimization for {storage_path}: {str(e)}")

        return url_path, False

    async def delete_file(self, file_path: str) -> bool:
        """Delete file from storage"""
        return await self.backend.delete_file(file_path)

    async def get_file_info(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Get file information"""
        if not await self.backend.file_exists(file_path):
            return None

        # For now, return basic info
        return {
            "path": file_path,
            "exists": True
        }

    async def cleanup_orphaned_files(self, valid_files: List[str], subdirectory: str = "files"):
        """Clean up orphaned files"""
        # This would need database integration to find valid files
        # For local storage, we can implement cleanup
        if hasattr(self.backend, 'cleanup_orphaned_files'):
            return await self.backend.cleanup_orphaned_files(valid_files)
        return 0

    async def get_storage_info(self) -> Dict[str, Any]:
        """Get storage backend information"""
        return await self.backend.get_storage_info()

    def update_server_limits(self):
        """Update file size limits from server settings"""
        try:
            server_settings = self.database_handler.get_server_settings()
            if server_settings:
                self.MAX_IMAGE_SIZE_MB = server_settings.max_image_size or 5
                self.MAX_VIDEO_SIZE_MB = server_settings.max_video_size or 50
                self.MAX_STICKER_SIZE_MB = server_settings.max_sticker_size or 5
                self.MAX_GIF_SIZE_MB = server_settings.max_gif_size or 10
                self.MAX_DOCUMENT_SIZE_MB = server_settings.max_message_length // 1000 or 10
                self.IMAGE_EXTENSIONS = server_settings.allowed_images_extensions or ['png', 'jpg', 'jpeg', 'gif', 'webp']
                self.STICKER_EXTENSIONS = server_settings.allowed_stickers_extensions or ['png', 'gif']
                self.GIF_EXTENSIONS = server_settings.allowed_gif_extensions or ['gif']
                self.VIDEO_EXTENSIONS = server_settings.allowed_videos_extensions or ['mp4', 'webm']
                self.DOCUMENT_EXTENSIONS = server_settings.allowed_doc_extensions or ['pdf', 'doc', 'docx', 'txt', 'zip']
        except Exception:
            pass  # Use defaults
