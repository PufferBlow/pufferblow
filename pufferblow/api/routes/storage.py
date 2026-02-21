"""
Storage and CDN Management Routes

This module contains all storage and CDN-related endpoints including:
- File uploads to storage/CDN
- File listing and information retrieval
- File deletion and cleanup operations
- File serving endpoints

All routes require server owner privileges except for file serving endpoints.
"""

import mimetypes
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Form, UploadFile, responses
from fastapi import exceptions
from pydantic import BaseModel, Field

from pufferblow.api.dependencies import require_server_owner
from pufferblow.api.logger.logger import logger
from pufferblow.api.schemas import (
    CDNDeleteFileRequest,
    CDNFileInfoRequest,
    CDNFilesRequest,
    CleanupOrphanedRequest,
)

# Import api_initializer - will be set by main api.py
api_initializer = None

# Create router
router = APIRouter()


def set_api_initializer(initializer: Any) -> None:
    """Set the API initializer for this module."""
    global api_initializer
    api_initializer = initializer


async def check_if_file_is_protected(file_url: str) -> bool:
    """
    Check if a file is currently in use as an avatar or banner.

    Args:
        file_url: The URL of the file to check

    Returns:
        bool: True if the file is protected (in use), False otherwise
    """
    try:
        # Check server avatar/banner
        server_data = api_initializer.database_handler.get_server()
        if server_data.avatar_url == file_url or server_data.banner_url == file_url:
            return True

        # Check user avatars/banners
        users = api_initializer.database_handler.get_all_users()
        for user in users:
            if user.avatar_url == file_url or user.banner_url == file_url:
                return True

        return False
    except Exception as e:
        logger.warning(f"Failed to check if file is protected: {str(e)}")
        return False  # If we can't check, allow deletion


@router.post("/api/v1/storage/upload", status_code=201)
async def upload_storage_file(
    auth_token: str,
    file: UploadFile = Form(..., description="File to upload"),
    directory: str = Form(
        ..., description="Target directory (uploads, avatars, banners, etc.)"
    ),
) -> dict:
    """
    Upload a file to storage. Server Owner only.

    Args:
        auth_token: User's authentication token
        file: File to upload
        directory: Target directory for upload

    Returns:
        201 CREATED: File uploaded successfully
        400 BAD REQUEST: File validation failed
        403 FORBIDDEN: User is not server owner
        404 NOT FOUND: Invalid auth_token
    """
    user_id = require_server_owner(auth_token)

    try:
        # Validate directory name for security
        allowed_dirs = [
            "uploads",
            "avatars",
            "banners",
            "attachments",
            "stickers",
            "gifs",
        ]
        if directory not in allowed_dirs:
            raise exceptions.HTTPException(
                status_code=400,
                detail=f"Invalid directory. Allowed: {', '.join(allowed_dirs)}",
            )

        # Use storage manager to handle the upload with categorization
        cdn_url, is_duplicate = (
            api_initializer.storage_manager.validate_and_save_categorized_file(
                file=file,
                user_id=user_id,
                force_category=directory if directory else None,
                check_duplicates=True,
            )
        )

        # Handle both new files and duplicates - update database accordingly
        try:
            # Extract file info from URL
            relative_path = cdn_url[len(api_initializer.config.CDN_BASE_URL) :].lstrip(
                "/"
            )
            file_path_obj = (
                Path(api_initializer.config.CDN_STORAGE_PATH) / relative_path
            )

            if file_path_obj.exists():
                # Read file to compute hash
                with open(file_path_obj, "rb") as f:
                    content = f.read()

                file_hash = api_initializer.cdn_manager.compute_file_hash(content)

                if is_duplicate:
                    # For duplicates, just increment the reference count
                    api_initializer.database_handler.increment_file_reference_count(
                        file_hash
                    )
                else:
                    # For new files, register and create reference
                    file_id = str(uuid.uuid4())  # Generate reference ID

                    # Register file in database
                    api_initializer.database_handler.create_file_object(
                        file_hash=file_hash,
                        ref_count=1,
                        file_path=relative_path,  # Store relative path
                        filename=file.filename,
                        file_size=len(content),
                        mime_type=api_initializer.cdn_manager.mime_detector.from_buffer(
                            content
                        )
                        or "application/octet-stream",
                        verification_status="verified",
                    )

                # Create reference for this upload (always)
                reference_id = f"cdn_upload_{uuid.uuid4()}"
                api_initializer.database_handler.create_file_reference(
                    reference_id=reference_id,
                    file_hash=file_hash,
                    reference_type="cdn_upload",
                    reference_entity_id=user_id,
                )
        except Exception as e:
            # Log but don't fail the upload - file is already saved
            logger.warning(f"Failed to update file metadata: {str(e)}")

        # Log file upload activity
        try:
            file_size = 0
            file_type = "unknown"

            if is_duplicate and cdn_url != api_initializer.config.CDN_BASE_URL:
                # For duplicates, get file size from existing file
                try:
                    relative_path = cdn_url[
                        len(api_initializer.config.CDN_BASE_URL) :
                    ].lstrip("/")
                    file_path_obj = (
                        Path(api_initializer.config.CDN_STORAGE_PATH) / relative_path
                    )
                    if file_path_obj.exists():
                        file_size = file_path_obj.stat().st_size
                        file_type = (
                            api_initializer.cdn_manager.mime_detector.from_file(
                                str(file_path_obj)
                            )
                            or "unknown"
                        )
                except Exception as e:
                    logger.warning(f"Failed to get duplicate file info: {str(e)}")
            elif "content" in locals():
                file_size = len(content)
                file_type = (
                    api_initializer.cdn_manager.mime_detector.from_buffer(content)
                    or "unknown"
                )

            # Create activity entry
            upload_type = (
                "existing file reused" if is_duplicate else "new file uploaded"
            )
            activity_data = {
                "event_type": "file_upload",
                "description": f"File '{file.filename}' {upload_type} to {directory}",
                "metadata": {
                    "file_url": cdn_url,
                    "file_size": file_size,
                    "file_type": file_type,
                    "directory": directory,
                    "uploader_id": user_id,
                    "is_duplicate": is_duplicate,
                },
                "user_id": user_id,
                "timestamp": datetime.utcnow().isoformat(),
            }

            api_initializer.database_handler.create_activity(activity_data)

            # Update activity metrics
            try:
                metrics = (
                    api_initializer.database_handler.calculate_daily_activity_metrics()
                )

                if metrics:
                    metrics.files_uploaded += 1
                    metrics.total_file_size_mb += (
                        (file_size / (1024 * 1024)) if file_size else 0
                    )
                    api_initializer.database_handler.save_activity_metrics(metrics)

            except Exception as e:
                logger.warning(f"Failed to update activity metrics: {str(e)}")

        except Exception as e:
            logger.warning(f"Failed to log file upload activity: {str(e)}")

        return {
            "status_code": 201,
            "message": (
                "File uploaded successfully"
                if not is_duplicate
                else "Duplicate file detected, existing file returned"
            ),
            "url": cdn_url,
            "is_duplicate": is_duplicate,
        }

    except exceptions.HTTPException:
        raise
    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500, detail=f"Upload failed: {str(e)}"
        )


@router.post("/api/v1/storage/files", status_code=200)
async def list_storage_files_route(request: CDNFilesRequest) -> dict:
    """
    List all files in a storage directory. Server Owner only.

    Args:
        request: Request containing auth_token and directory

    Returns:
        200 OK: List of files with metadata
        403 FORBIDDEN: User is not server owner
        404 NOT FOUND: Invalid auth_token
    """
    user_id = require_server_owner(request.auth_token)

    try:
        cdn_base = Path(api_initializer.config.CDN_STORAGE_PATH)
        all_files_info = []

        # Check what directories exist
        existing_dirs = []
        if cdn_base.exists():
            logger.info(f"CDN base directory exists: {cdn_base}")
            for item in cdn_base.iterdir():
                if item.is_dir():
                    existing_dirs.append(item.name)
            logger.info(f"Found existing directories: {existing_dirs}")
        else:
            logger.error(f"CDN base directory does not exist: {cdn_base}")

        # Directory mapping
        directory_map = {
            "uploads": ["images", "videos", "documents", "files", "uploads"],
            "avatars": ["avatars"],
            "banners": ["banners"],
            "attachments": ["images", "videos", "documents"],
            "stickers": ["stickers"],
            "gifs": ["gifs"],
            "all": None,
        }

        if request.directory == "all":
            logger.info(f"Listing files from ALL directories: {existing_dirs}")
            for sub_dir_name in existing_dirs:
                sub_dir = cdn_base / sub_dir_name
                if sub_dir.exists():
                    for file_path in sub_dir.glob("*"):
                        if file_path.is_file():
                            stat = file_path.stat()
                            all_files_info.append(
                                {
                                    "filename": file_path.name,
                                    "size": stat.st_size,
                                    "modified": stat.st_mtime,
                                    "url": f"{api_initializer.config.CDN_BASE_URL}/{sub_dir_name}/{file_path.name}",
                                    "subdirectory": sub_dir_name,
                                }
                            )
        else:
            # Check specific directories
            subdirectories = directory_map.get(request.directory, [request.directory])

            # Check if directory exists directly
            if Path(cdn_base / request.directory).exists():
                subdirectories.append(request.directory)

            # Remove duplicates
            subdirectories = list(set(subdirectories))

            for sub_dir_name in subdirectories:
                sub_dir = cdn_base / sub_dir_name
                if sub_dir.exists():
                    for file_path in sub_dir.glob("*"):
                        if file_path.is_file():
                            stat = file_path.stat()

                            # Detect MIME type
                            mime_type = (
                                api_initializer.cdn_manager.mime_detector.from_file(
                                    str(file_path)
                                )
                                or "application/octet-stream"
                            )

                            # Try to determine uploader
                            uploader_username = "Unknown"
                            try:
                                filename_parts = file_path.name.split("_")
                                if len(filename_parts) >= 2:
                                    if filename_parts[0] == "server":
                                        uploader_username = "Server Owner"
                                    elif filename_parts[0] == "user":
                                        uploader_username = "User"
                            except Exception:
                                pass

                            # Better MIME type detection for text files
                            file_extension = (
                                file_path.name.split(".")[-1].lower()
                                if "." in file_path.name
                                else ""
                            )
                            text_extensions = [
                                "txt",
                                "py",
                                "js",
                                "ts",
                                "json",
                                "yml",
                                "yaml",
                                "md",
                                "toml",
                                "html",
                                "css",
                                "xml",
                                "csv",
                                "log",
                            ]

                            if (
                                mime_type == "application/octet-stream"
                                and file_extension in text_extensions
                            ):
                                mime_type = "text/plain"

                            all_files_info.append(
                                {
                                    "filename": file_path.name,
                                    "size": stat.st_size,
                                    "modified": stat.st_mtime,
                                    "url": f"{api_initializer.config.CDN_BASE_URL}/{sub_dir_name}/{file_path.name}",
                                    "subdirectory": sub_dir_name,
                                    "type": mime_type,
                                    "uploader": uploader_username,
                                }
                            )

        logger.info(f"Total files found: {len(all_files_info)}")

        return {
            "status_code": 200,
            "directory": request.directory,
            "files": all_files_info,
            "existing_dirs": existing_dirs,
            "scanned_dirs": (
                subdirectories if request.directory != "all" else existing_dirs
            ),
        }

    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500, detail=f"Failed to list CDN files: {str(e)}"
        )


@router.post("/api/v1/storage/file-info", status_code=200)
async def get_storage_file_info_route(request: CDNFileInfoRequest) -> dict:
    """
    Get information about a specific storage file. Server Owner only.

    Args:
        request: Request containing auth_token and file_url

    Returns:
        200 OK: File information
        403 FORBIDDEN: User is not server owner
        404 NOT FOUND: File not found or invalid auth_token
    """
    user_id = require_server_owner(request.auth_token)

    file_info = api_initializer.cdn_manager.get_file_info(request.file_url)
    if file_info is None:
        raise exceptions.HTTPException(status_code=404, detail="File not found")

    return {
        "status_code": 200,
        "file_info": {
            "url": request.file_url,
            "size": file_info.get("size"),
            "mime_type": file_info.get("mime_type"),
            "created": file_info.get("created"),
            "modified": file_info.get("modified"),
        },
    }


@router.post("/api/v1/storage/delete-file", status_code=200)
async def delete_storage_file_route(request: CDNDeleteFileRequest) -> dict:
    """
    Delete a file from storage. Server Owner only.
    Prevents deletion of avatar/banner files that are currently in use.

    Args:
        request: Request containing auth_token and file_url

    Returns:
        200 OK: File deleted successfully
        403 FORBIDDEN: User is not server owner or file is protected
        404 NOT FOUND: File not found or invalid auth_token
        500 INTERNAL SERVER ERROR: Deletion failed
    """
    user_id = require_server_owner(request.auth_token)

    try:
        # Check if the file is currently used as an avatar or banner
        is_protected = await check_if_file_is_protected(request.file_url)
        if is_protected:
            raise exceptions.HTTPException(
                status_code=403,
                detail="Cannot delete this file as it is currently used as a user or server avatar/banner.",
            )

        deleted = api_initializer.cdn_manager.delete_file(request.file_url)
        if not deleted:
            raise exceptions.HTTPException(status_code=404, detail="File not found")

        return {
            "status_code": 200,
            "message": "File deleted successfully",
            "file_url": request.file_url,
        }

    except exceptions.HTTPException:
        raise
    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500, detail=f"Failed to delete file: {str(e)}"
        )


@router.post("/api/v1/storage/cleanup-orphaned", status_code=200)
async def cleanup_orphaned_storage_files_route(
    request: CleanupOrphanedRequest,
) -> dict:
    """
    Remove CDN files that are no longer referenced in the database.
    Server Owner only.

    Args:
        request: Request containing auth_token and subdirectory

    Returns:
        200 OK: Cleanup completed
        403 FORBIDDEN: User is not server owner
        404 NOT FOUND: Invalid auth_token
        500 INTERNAL SERVER ERROR: Cleanup failed
    """
    user_id = require_server_owner(request.auth_token)

    try:
        # Get list of referenced files from database
        db_files = []

        # Collect avatar URLs from users
        if request.subdirectory == "avatars":
            try:
                users = api_initializer.database_handler.get_all_users()
                for user in users:
                    if user.avatar_url:
                        db_files.append(user.avatar_url)
            except Exception:
                pass

        # Collect banner URLs from users
        elif request.subdirectory == "banners":
            try:
                users = api_initializer.database_handler.get_all_users()
                for user in users:
                    if user.banner_url:
                        db_files.append(user.banner_url)
            except Exception:
                pass

        # Collect server avatar/banner
        elif request.subdirectory == "server":
            try:
                server_data = api_initializer.database_handler.get_server()
                if server_data.avatar_url:
                    db_files.append(server_data.avatar_url)
                if server_data.banner_url:
                    db_files.append(server_data.banner_url)
            except Exception:
                pass

        # For other directories, not yet implemented
        else:
            return {
                "status_code": 200,
                "message": f"Cleanup for subdirectory '{request.subdirectory}' is not yet implemented. Currently only avatars, banners, and server directories are supported.",
            }

        api_initializer.cdn_manager.cleanup_orphaned_files(
            db_files, request.subdirectory
        )

        return {
            "status_code": 200,
            "message": "Orphaned files cleanup completed successfully",
            "subdirectory": request.subdirectory,
        }

    except Exception as e:
        raise exceptions.HTTPException(
            status_code=500, detail=f"Cleanup failed: {str(e)}"
        )


@router.get("/api/v1/cdn/file/{file_path:path}", status_code=200)
async def serve_cdn_file_route(
    file_path: str, auth_token: str = None
) -> responses.Response:
    """
    Serve a CDN file directly with validation and optional authentication.

    This route provides secure access to CDN files with file validation.
    Use this when you need authenticated access to CDN files.

    Args:
        file_path: The file path relative to the CDN storage directory
        auth_token: Optional authentication token

    Returns:
        200 OK: File served
        404 NOT FOUND: File not found
        403 FORBIDDEN: Authentication required but invalid
        500 INTERNAL SERVER ERROR: Failed to serve file
    """
    try:
        # Verify file exists on filesystem
        cdn_storage_path = Path(api_initializer.config.CDN_STORAGE_PATH) / file_path
        if not cdn_storage_path.exists() or not cdn_storage_path.is_file():
            raise exceptions.HTTPException(status_code=404, detail="File not found")

        # Optional auth check if provided
        if auth_token:
            try:
                from pufferblow.api.dependencies import get_current_user

                get_current_user(auth_token)
            except Exception:
                raise exceptions.HTTPException(
                    status_code=403, detail="Invalid authentication token"
                )

        # Get MIME type
        content_type, _ = mimetypes.guess_type(cdn_storage_path.name)
        if not content_type:
            content_type = "application/octet-stream"

        # Read and return file
        with open(cdn_storage_path, "rb") as file:
            content = file.read()

        return responses.Response(
            content=content,
            media_type=content_type,
            headers={
                "Content-Disposition": f"inline; filename={cdn_storage_path.name}"
            },
        )

    except exceptions.HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to serve file {file_path}: {str(e)}")
        raise exceptions.HTTPException(status_code=500, detail="Failed to serve file")


@router.get("/api/v1/storage/file/{file_path:path}", status_code=200)
async def serve_storage_file_route(
    file_path: str, auth_token: str = None
) -> responses.Response:
    """
    Serve a storage file directly with validation and optional authentication.

    This route provides secure access to storage files with file validation.
    Use this when you need authenticated access to storage files.

    Args:
        file_path: The file path relative to the storage directory
        auth_token: Optional authentication token

    Returns:
        200 OK: File served
        404 NOT FOUND: File not found
        403 FORBIDDEN: Authentication required but invalid
        500 INTERNAL SERVER ERROR: Failed to serve file
    """
    try:
        # Verify file exists on filesystem
        storage_path = Path(api_initializer.config.STORAGE_PATH) / file_path
        if not storage_path.exists() or not storage_path.is_file():
            raise exceptions.HTTPException(status_code=404, detail="File not found")

        # Optional auth check if provided
        if auth_token:
            try:
                from pufferblow.api.dependencies import get_current_user

                get_current_user(auth_token)
            except Exception:
                raise exceptions.HTTPException(
                    status_code=403, detail="Invalid authentication token"
                )

        # Get MIME type
        content_type, _ = mimetypes.guess_type(storage_path.name)
        if not content_type:
            content_type = "application/octet-stream"

        # Read and return file
        with open(storage_path, "rb") as file:
            content = file.read()

        return responses.Response(
            content=content,
            media_type=content_type,
            headers={"Content-Disposition": f"inline; filename={storage_path.name}"},
        )

    except exceptions.HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to serve storage file {file_path}: {str(e)}")
        raise exceptions.HTTPException(status_code=500, detail="Failed to serve file")


@router.get("/storage/{file_hash}", status_code=200)
async def serve_file_by_hash(file_hash: str):
    """
    Serve a file by its content hash.

    Looks up the hash in `file_objects`, resolves the file path,
    and returns the file bytes through storage manager read flow.
    """
    try:
        file_object = api_initializer.database_handler.get_file_object_by_hash(
            file_hash
        )
        if not file_object:
            raise exceptions.HTTPException(status_code=404, detail="File not found")

        file_path = file_object.file_path
        storage_path = Path(api_initializer.config.STORAGE_PATH) / file_path
        if not storage_path.exists() or not storage_path.is_file():
            raise exceptions.HTTPException(
                status_code=404, detail="File not found on disk"
            )

        content_type, _ = mimetypes.guess_type(storage_path.name)
        if not content_type:
            content_type = file_object.mime_type or "application/octet-stream"

        content = await api_initializer.storage_manager.read_file_content(file_path)

        return responses.Response(
            content=content,
            media_type=content_type,
            headers={"Content-Disposition": f"inline; filename={storage_path.name}"},
        )
    except exceptions.HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to serve file by hash {file_hash}: {str(e)}")
        raise exceptions.HTTPException(status_code=500, detail="Failed to serve file")
