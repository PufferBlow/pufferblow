import hashlib
import mimetypes
import uuid
from io import BytesIO
from pathlib import Path

import magic  # python-magic for MIME detection
from fastapi import HTTPException, UploadFile
from PIL import Image

from pufferblow.api.database.database_handler import DatabaseHandler
from pufferblow.api.models.config_model import Config


class CDNManager:
    """CDN Manager for handling file uploads and serving"""

    def __init__(self, database_handler: DatabaseHandler, config: Config):
        """Initialize the instance."""
        self.database_handler = database_handler
        self.config = config

        # Create storage directory if it doesn't exist
        Path(self.config.CDN_STORAGE_PATH).mkdir(parents=True, exist_ok=True)

        # Initialize MIME detector
        self.mime_detector = magic.Magic(mime=True)

        # File type validation - defaults, will be updated from server settings
        self.IMAGE_EXTENSIONS = ["png", "jpg", "jpeg", "gif", "webp"]
        self.STICKER_EXTENSIONS = ["png", "gif"]
        self.GIF_EXTENSIONS = ["gif"]
        self.VIDEO_EXTENSIONS = ["mp4", "webm", "mov", "avi"]
        self.DOCUMENT_EXTENSIONS = ["pdf", "doc", "docx", "txt", "zip"]
        self.MAX_IMAGE_SIZE_MB = 5  # Default, will be updated from server settings
        self.MAX_VIDEO_SIZE_MB = 50
        self.MAX_STICKER_SIZE_MB = 5
        self.MAX_GIF_SIZE_MB = 10
        self.MAX_DOCUMENT_SIZE_MB = 10

    def compute_file_hash(self, content: bytes) -> str:
        """
        Compute SHA-256 hash of file content

        Args:
            content: File content bytes

        Returns:
            Hexadecimal string of the hash
        """
        return hashlib.sha256(content).hexdigest()

    def categorize_file(self, filename: str, mime_type: str) -> str:
        """
        Automatically categorize a file based on its type and return the appropriate subdirectory

        Args:
            filename: Name of the uploaded file
            mime_type: MIME type detected from file content

        Returns:
            Appropriate subdirectory name for the file type
        """
        extension = filename.split(".")[-1].lower() if "." in filename else ""

        # Categorize based on MIME type and extension priority
        if mime_type.startswith("image/"):
            # Special handling for GIFs
            if extension in self.GIF_EXTENSIONS:
                return "gifs"
            # Special handling for stickers (typically smaller PNG/GIF files)
            elif (
                extension in self.STICKER_EXTENSIONS and "_sticker" in filename.lower()
            ):
                return "stickers"
            # Avatar and banner images
            elif "_avatar" in filename.lower():
                return "avatars"
            elif "_banner" in filename.lower():
                return "banners"
            else:
                # General images
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

    def find_duplicate_by_hash(
        self, file_hash: str, subdirectory: str
    ) -> str | None:
        """
        Check if a file with the same hash already exists in the subdirectory

        Args:
            file_hash: SHA-256 hash of the file
            subdirectory: Subdirectory to search in

        Returns:
            URL path if duplicate found, None otherwise
        """
        sub_dir = Path(self.config.CDN_STORAGE_PATH) / subdirectory
        if not sub_dir.exists():
            return None

        # Check existing files for hash match
        for existing_file in sub_dir.glob("*"):
            if existing_file.is_file():
                try:
                    with open(existing_file, "rb") as f:
                        existing_content = f.read()
                    existing_hash = self.compute_file_hash(existing_content)
                    if existing_hash == file_hash:
                        # Found duplicate, return URL
                        return f"{self.config.CDN_BASE_URL}/{subdirectory}/{existing_file.name}"
                except Exception:
                    # Skip files that can't be read
                    continue

        return None

    def validate_and_save_categorized_file(
        self,
        file: UploadFile,
        user_id: str,
        check_duplicates: bool = True,
        force_category: str | None = None,
    ) -> tuple[str, bool]:
        """
        Validate and save an uploaded file with automatic categorization based on file type

        Args:
            file: FastAPI UploadFile object
            user_id: Owner user ID
            check_duplicates: Whether to check for duplicate files using hash
            force_category: Force a specific category (optional)

        Returns:
            Tuple of (File URL path relative to base URL, is_duplicate)

        Raises:
            HTTPException: If validation fails
        """
        # Check file size first (use content to determine limits)
        content = file.file.read()
        filename = file.filename or "unknown"
        extension = filename.split(".")[-1].lower() if "." in filename else ""

        # Detect MIME type
        mime_type = self.mime_detector.from_buffer(content)
        if not mime_type:
            raise HTTPException(status_code=400, detail="Cannot determine file type")

        # Determine category and limits
        category = (
            force_category
            if force_category
            else self.categorize_file(filename, mime_type)
        )

        # Set appropriate limits based on category
        if category == "images":
            max_size_mb = self.MAX_IMAGE_SIZE_MB
            allowed_extensions = self.IMAGE_EXTENSIONS
        elif category == "avatars":
            max_size_mb = self.MAX_IMAGE_SIZE_MB
            allowed_extensions = self.IMAGE_EXTENSIONS
        elif category == "banners":
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
            max_size_mb = 10  # Default 10MB for unknown types
            allowed_extensions = [extension] if extension else ["*"]

        # Reset file pointer for validation
        file.file.seek(0)

        # Use the standard validation method with determined category
        return self.validate_and_save_file(
            file=file,
            user_id=user_id,
            max_size_mb=max_size_mb,
            allowed_extensions=allowed_extensions,
            subdirectory=category,
            check_duplicates=check_duplicates,
        )

    def validate_and_save_file(
        self,
        file: UploadFile,
        user_id: str,
        max_size_mb: int,
        allowed_extensions: list[str],
        subdirectory: str = "files",
        check_duplicates: bool = True,
    ) -> tuple[str, bool]:
        """
        Validate and save an uploaded file, with optional duplicate checking

        Args:
            file: FastAPI UploadFile object
            user_id: Owner user ID
            max_size_mb: Maximum file size in MB
            allowed_extensions: List of allowed file extensions
            subdirectory: Subdirectory within CDN storage (e.g., "avatars")
            check_duplicates: Whether to check for duplicate files using hash

        Returns:
            Tuple of (File URL path relative to base URL, is_duplicate)

        Raises:
            HTTPException: If validation fails
        """
        from pathlib import Path

        # Check file size
        content = file.file.read()
        if len(content) > max_size_mb * 1024 * 1024 * 30:
            raise HTTPException(
                status_code=400, detail=f"File size exceeds maximum of {max_size_mb}MB"
            )

        # Detect MIME type from content
        mime_type = self.mime_detector.from_buffer(content)
        if not mime_type:
            raise HTTPException(status_code=400, detail="Cannot determine file type")

        # Validate extension
        filename = file.filename or "unknown"
        extension = filename.split(".")[-1].lower() if "." in filename else ""
        if extension not in allowed_extensions and "*" not in allowed_extensions:
            raise HTTPException(
                status_code=400,
                detail=f"File extension '{extension}' not allowed. Allowed: {', '.join(allowed_extensions)}",
            )

        # Additional validation for documents (PDFs, Office docs)
        if extension in self.DOCUMENT_EXTENSIONS:
            # For documents, just check basic MIME type matching
            expected_mime = {
                "pdf": "application/pdf",
                "doc": "application/msword",
                "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "txt": "text/plain",
                "zip": "application/zip",
            }.get(extension)

            if expected_mime and not mime_type.startswith(expected_mime.split("/")[0]):
                raise HTTPException(
                    status_code=400,
                    detail=f"File content doesn't match extension. Expected {expected_mime}, got {mime_type}",
                )

        # For image files, validate dimensions and format
        if extension in self.IMAGE_EXTENSIONS and mime_type.startswith("image/"):
            try:
                image = Image.open(BytesIO(content))
                image.verify()  # Verify it's a valid image
                image = Image.open(BytesIO(content))
                max_dimension = 2048  # Max width/height
                if image.size[0] > max_dimension or image.size[1] > max_dimension:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Image dimensions too large. Max allowed: {max_dimension}x{max_dimension}",
                    )
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid image file")

        # Check for duplicate files using hash (if enabled)
        is_duplicate = False
        file_hash = ""
        if check_duplicates and len(content) > 0:  # Skip for empty files
            file_hash = self.compute_file_hash(content)
            existing_url = self.find_duplicate_by_hash(file_hash, subdirectory)

            if existing_url:
                # Return existing file URL as duplicate
                return existing_url, True

        # Generate unique filename
        file_id = str(uuid.uuid4())
        new_filename = f"{file_id}.{extension}"

        # Create subdirectory path
        sub_dir = Path(self.config.CDN_STORAGE_PATH) / subdirectory
        sub_dir.mkdir(parents=True, exist_ok=True)

        # Full file path
        file_path = sub_dir / new_filename

        # Save file
        with open(file_path, "wb") as f:
            f.write(content)

        # Generate URL path
        url_path = f"{self.config.CDN_BASE_URL}/{subdirectory}/{new_filename}"

        # Register file in database (only in production, not SQLite tests)
        # We'll use a reference type of 'cdn_upload' for CDN management
        try:
            from pufferblow.core.bootstrap import api_initializer

            if file_hash == "":
                file_hash = self.compute_file_hash(content)

            # Create file object in database
            api_initializer.database_handler.create_file_object(
                file_hash=file_hash,
                ref_count=1,  # Initial reference count
                file_path=f"{subdirectory}/{new_filename}",
                filename=filename,
                file_size=len(content),
                mime_type=mime_type,
                verification_status="verified",
            )

            # Create file reference for this upload
            reference_id = f"cdn_upload_{file_id}"
            api_initializer.database_handler.create_file_reference(
                reference_id=reference_id,
                file_hash=file_hash,
                reference_type="cdn_upload",
                reference_entity_id=user_id,  # Owner of the upload
            )

        except Exception:
            # Log error but don't fail the upload (file is saved, just not tracked)
            # TODO: Add proper logging
            pass

        return url_path, False

    def delete_file(self, file_url: str) -> bool:
        """
        Delete a file by its URL

        Args:
            file_url: Full URL path

        Returns:
            True if deleted, False if not found
        """
        # Convert URL to file path
        relative_path = file_url[len(self.config.CDN_BASE_URL) :].lstrip("/")
        file_path = Path(self.config.CDN_STORAGE_PATH) / relative_path

        if file_path.exists():
            file_path.unlink()
            return True
        return False

    def get_file_info(self, file_url: str) -> dict | None:
        """
        Get file information by URL

        Args:
            file_url: File URL

        Returns:
            Dict with file info or None if not found
        """
        relative_path = file_url[len(self.config.CDN_BASE_URL) :].lstrip("/")
        file_path = Path(self.config.CDN_STORAGE_PATH) / relative_path

        if not file_path.exists():
            return None

        stat = file_path.stat()
        mime_type, _ = mimetypes.guess_type(file_path)

        return {
            "path": file_path,
            "size": stat.st_size,
            "mime_type": mime_type,
            "created": stat.st_ctime,
            "modified": stat.st_mtime,
        }

    def cleanup_orphaned_files(self, db_files: list[str], subdirectory: str = "files"):
        """
        Remove files that are no longer referenced in database

        Args:
            db_files: List of file URLs that should exist
            subdirectory: Subdirectory to clean
        """
        sub_dir = Path(self.config.CDN_STORAGE_PATH) / subdirectory
        if not sub_dir.exists():
            return

        url_prefix = f"{self.config.CDN_BASE_URL}/{subdirectory}/"

        for file_path in sub_dir.glob("*"):
            file_url = f"{url_prefix}{file_path.name}"
            if file_url not in db_files:
                file_path.unlink()

    def update_server_limits(self):
        """Update file size limits and allowed extensions from server settings (called periodically or on startup)"""
        try:
            server_settings = self.database_handler.get_server_settings()
            if server_settings:
                self.MAX_IMAGE_SIZE_MB = server_settings.max_image_size or 5
                self.MAX_VIDEO_SIZE_MB = server_settings.max_video_size or 50
                self.MAX_STICKER_SIZE_MB = server_settings.max_sticker_size or 5
                self.MAX_GIF_SIZE_MB = server_settings.max_gif_size or 10
                self.MAX_DOCUMENT_SIZE_MB = (
                    server_settings.max_message_length // 1000 or 10
                )  # Rough estimate
                self.IMAGE_EXTENSIONS = server_settings.allowed_images_extensions or [
                    "png",
                    "jpg",
                    "jpeg",
                    "gif",
                    "webp",
                ]
                self.STICKER_EXTENSIONS = (
                    server_settings.allowed_stickers_extensions or ["png", "gif"]
                )
                self.GIF_EXTENSIONS = server_settings.allowed_gif_extensions or ["gif"]
                self.VIDEO_EXTENSIONS = server_settings.allowed_videos_extensions or [
                    "mp4",
                    "webm",
                ]
                self.DOCUMENT_EXTENSIONS = server_settings.allowed_doc_extensions or [
                    "pdf",
                    "doc",
                    "docx",
                    "txt",
                    "zip",
                ]
        except Exception:
            # Use defaults if DB not available
            pass
