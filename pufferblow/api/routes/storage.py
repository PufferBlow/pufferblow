"""Storage management routes."""

from __future__ import annotations

import mimetypes
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Form, UploadFile, exceptions, responses
from sqlalchemy import delete, select

from pufferblow.api.database.tables.file_objects import FileObjects, FileReferences
from pufferblow.api.dependencies import require_server_owner
from pufferblow.api.logger.logger import logger
from pufferblow.api.schemas import (
    CleanupOrphanedRequest,
    StorageDeleteFileRequest,
    StorageFileInfoRequest,
    StorageFilesRequest,
)

# Import api_initializer - will be set by register.py
api_initializer = None

router = APIRouter()

ALLOWED_UPLOAD_DIRECTORIES: set[str] = {
    "uploads",
    "avatars",
    "banners",
    "attachments",
    "stickers",
    "gifs",
    "images",
    "videos",
    "audio",
    "documents",
    "files",
    "config",
}

DIRECTORY_EXPANSION_MAP: dict[str, list[str]] = {
    "uploads": ["uploads", "attachments", "images", "videos", "audio", "documents", "files"],
    "attachments": ["attachments", "images", "videos", "audio", "documents", "files"],
    "avatars": ["avatars"],
    "banners": ["banners"],
    "stickers": ["stickers"],
    "gifs": ["gifs"],
    "images": ["images"],
    "videos": ["videos"],
    "audio": ["audio"],
    "documents": ["documents"],
    "files": ["files"],
    "config": ["config"],
    "server": ["avatars", "banners"],
}


def set_api_initializer(initializer: Any) -> None:
    """Set the API initializer for this module."""
    global api_initializer
    api_initializer = initializer


def _is_hash(value: str) -> bool:
    """Check if a string looks like a SHA-256 hex hash."""
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value.lower())


def _extract_path_from_url(file_url: str) -> str:
    """Extract URL path part from absolute/relative file URL."""
    if "://" in file_url:
        return urlparse(file_url).path
    return file_url


def _get_storage_root() -> Path:
    """Return storage root path."""
    return Path(api_initializer.config.STORAGE_PATH)


def _file_hash_from_relative_path(relative_path: str) -> str | None:
    """Lookup file hash for a relative storage path."""
    try:
        with api_initializer.database_handler.database_session() as session:
            stmt = select(FileObjects.file_hash).where(
                FileObjects.file_path == relative_path
            )
            return session.execute(stmt).scalar_one_or_none()
    except Exception:
        return None


def _relative_path_from_hash(file_hash: str) -> str | None:
    """Resolve storage relative path from file hash."""
    file_obj = api_initializer.database_handler.get_file_object_by_hash(file_hash)
    if not file_obj:
        return None
    return file_obj.file_path


def _resolve_storage_relative_path(file_url: str) -> str | None:
    """Resolve a relative storage path from any supported storage URL."""
    raw_path = _extract_path_from_url(file_url).strip()
    if not raw_path:
        return None

    storage_base = api_initializer.config.STORAGE_BASE_URL.rstrip("/")
    storage_base_segment = storage_base.lstrip("/")
    storage_api_prefix = "/api/v1/storage/file/"

    if raw_path.startswith(storage_api_prefix):
        relative = raw_path[len(storage_api_prefix) :].lstrip("/")
        return relative or None

    if raw_path.startswith(f"{storage_base}/"):
        suffix = raw_path[len(storage_base) + 1 :]
        # Hash URL format: /storage/<file_hash>
        if "/" not in suffix and _is_hash(suffix):
            return _relative_path_from_hash(suffix)
        return suffix or None

    normalized = raw_path.lstrip("/")
    if _is_hash(normalized):
        return _relative_path_from_hash(normalized)

    if storage_base_segment and normalized.startswith(f"{storage_base_segment}/"):
        suffix = normalized[len(storage_base_segment) + 1 :]
        if "/" not in suffix and _is_hash(suffix):
            return _relative_path_from_hash(suffix)
        return suffix or None

    if "/" in normalized:
        return normalized

    return None


def _canonical_file_identity(file_url: str) -> str:
    """
    Build canonical identity for comparisons:
    - hash:<sha256> when possible
    - path:<relative/path>
    - fallback to raw URL string
    """
    raw_path = _extract_path_from_url(file_url).strip()
    if not raw_path:
        return ""

    storage_base = api_initializer.config.STORAGE_BASE_URL.rstrip("/")
    if raw_path.startswith(f"{storage_base}/"):
        suffix = raw_path[len(storage_base) + 1 :]
        if "/" not in suffix and _is_hash(suffix):
            return f"hash:{suffix}"

    normalized = raw_path.lstrip("/")
    if _is_hash(normalized):
        return f"hash:{normalized}"

    relative_path = _resolve_storage_relative_path(file_url)
    if relative_path:
        file_hash = _file_hash_from_relative_path(relative_path)
        if file_hash:
            return f"hash:{file_hash}"
        return f"path:{relative_path}"

    return raw_path


def _build_public_storage_url(relative_path: str) -> str:
    """
    Build canonical public URL for a relative storage path.

    Prefer hash URLs (`/storage/<hash>`) so SSE-enabled storage serves
    decrypted content through route handlers.
    """
    file_hash = _file_hash_from_relative_path(relative_path)
    if file_hash:
        return f"{api_initializer.config.STORAGE_BASE_URL.rstrip('/')}/{file_hash}"
    return f"/api/v1/storage/file/{relative_path}"


async def _is_file_protected(file_url: str) -> bool:
    """
    Check if a file is currently in use as an avatar or banner.
    """
    try:
        target = _canonical_file_identity(file_url)
        if not target:
            return False

        server_data = api_initializer.database_handler.get_server()
        server_urls = [server_data.avatar_url, server_data.banner_url]
        if any(_canonical_file_identity(url or "") == target for url in server_urls):
            return True

        users = api_initializer.database_handler.get_all_users()
        for user in users:
            if _canonical_file_identity(user.avatar_url or "") == target:
                return True
            if _canonical_file_identity(user.banner_url or "") == target:
                return True

        return False
    except Exception as exc:
        logger.warning(f"Failed to check protected file state: {exc}")
        return False


def _resolve_upload_category(directory: str) -> str | None:
    """Resolve user-facing upload directory to storage category."""
    if directory in {"uploads", "attachments"}:
        return None
    return directory


def _target_directories(directory: str, existing_dirs: list[str]) -> list[str]:
    """Expand a logical directory into concrete storage directories."""
    if directory == "all":
        return existing_dirs
    mapped = DIRECTORY_EXPANSION_MAP.get(directory)
    if mapped:
        return mapped
    return [directory]


def _load_referenced_paths() -> set[str]:
    """Load all referenced relative file paths from database."""
    try:
        with api_initializer.database_handler.database_session() as session:
            rows = session.execute(
                select(FileObjects.file_path)
                .join(FileReferences, FileReferences.file_hash == FileObjects.file_hash)
                .distinct()
            ).all()
        return {str(row[0]).replace("\\", "/") for row in rows if row[0]}
    except Exception:
        return set()


def _remove_file_metadata(file_hash: str) -> None:
    """Delete file object + references for a removed file hash."""
    try:
        with api_initializer.database_handler.database_session() as session:
            session.execute(
                delete(FileReferences).where(FileReferences.file_hash == file_hash)
            )
            session.execute(delete(FileObjects).where(FileObjects.file_hash == file_hash))
            session.commit()
    except Exception as exc:
        logger.warning(f"Failed to delete file metadata for hash {file_hash}: {exc}")


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
    """
    user_id = require_server_owner(auth_token)

    if directory not in ALLOWED_UPLOAD_DIRECTORIES:
        raise exceptions.HTTPException(
            status_code=400,
            detail=f"Invalid directory. Allowed: {', '.join(sorted(ALLOWED_UPLOAD_DIRECTORIES))}",
        )

    try:
        storage_url, is_duplicate = (
            await api_initializer.storage_manager.validate_and_save_categorized_file(
                file=file,
                user_id=user_id,
                force_category=_resolve_upload_category(directory),
                check_duplicates=True,
            )
        )

        try:
            activity_data = {
                "event_type": "file_upload",
                "description": f"File '{file.filename}' uploaded to storage ({directory})",
                "metadata": {
                    "file_url": storage_url,
                    "directory": directory,
                    "uploader_id": user_id,
                    "is_duplicate": is_duplicate,
                },
                "user_id": user_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            api_initializer.database_handler.create_activity(activity_data)
        except Exception as exc:
            logger.warning(f"Failed to write upload activity log: {exc}")

        return {
            "status_code": 201,
            "message": (
                "File uploaded successfully"
                if not is_duplicate
                else "Duplicate file detected, existing file returned"
            ),
            "url": storage_url,
            "is_duplicate": is_duplicate,
        }
    except exceptions.HTTPException:
        raise
    except Exception as exc:
        raise exceptions.HTTPException(
            status_code=500, detail=f"Upload failed: {str(exc)}"
        )


@router.post("/api/v1/storage/files", status_code=200)
async def list_storage_files_route(request: StorageFilesRequest) -> dict:
    """
    List files in storage directories. Server Owner only.
    """
    require_server_owner(request.auth_token)

    storage_root = _get_storage_root()
    if not storage_root.exists():
        return {
            "status_code": 200,
            "directory": request.directory,
            "files": [],
            "existing_dirs": [],
            "scanned_dirs": [],
        }

    existing_dirs = sorted(
        item.name for item in storage_root.iterdir() if item.is_dir()
    )
    target_dirs = _target_directories(request.directory, existing_dirs)
    scanned_dirs = [d for d in target_dirs if (storage_root / d).exists()]

    files: list[dict[str, Any]] = []
    for directory in scanned_dirs:
        sub_dir = storage_root / directory
        for file_path in sorted(sub_dir.glob("*")):
            if not file_path.is_file():
                continue

            stat = file_path.stat()
            mime_type, _ = mimetypes.guess_type(file_path.name)
            relative_path = str(file_path.relative_to(storage_root)).replace("\\", "/")
            file_hash = _file_hash_from_relative_path(relative_path)

            files.append(
                {
                    "id": file_hash or relative_path,
                    "filename": file_path.name,
                    "size": stat.st_size,
                    "uploaded_at": datetime.fromtimestamp(
                        stat.st_mtime, tz=timezone.utc
                    ).isoformat(),
                    "modified": stat.st_mtime,
                    "url": _build_public_storage_url(relative_path),
                    "subdirectory": directory,
                    "type": mime_type or "application/octet-stream",
                    "uploader": "Unknown",
                    "is_orphaned": False,
                }
            )

    return {
        "status_code": 200,
        "directory": request.directory,
        "files": files,
        "existing_dirs": existing_dirs,
        "scanned_dirs": scanned_dirs,
    }


@router.post("/api/v1/storage/file-info", status_code=200)
async def get_storage_file_info_route(request: StorageFileInfoRequest) -> dict:
    """
    Get metadata for a storage file. Server Owner only.
    """
    require_server_owner(request.auth_token)

    relative_path = _resolve_storage_relative_path(request.file_url)
    if not relative_path:
        raise exceptions.HTTPException(status_code=404, detail="File not found")

    storage_path = _get_storage_root() / relative_path
    if not storage_path.exists() or not storage_path.is_file():
        raise exceptions.HTTPException(status_code=404, detail="File not found")

    stat = storage_path.stat()
    mime_type, _ = mimetypes.guess_type(storage_path.name)
    file_hash = _file_hash_from_relative_path(relative_path)

    return {
        "status_code": 200,
        "file_info": {
            "url": _build_public_storage_url(relative_path),
            "path": relative_path,
            "size": stat.st_size,
            "mime_type": mime_type or "application/octet-stream",
            "created": datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat(),
            "modified": datetime.fromtimestamp(
                stat.st_mtime, tz=timezone.utc
            ).isoformat(),
            "file_hash": file_hash,
        },
    }


@router.post("/api/v1/storage/delete-file", status_code=200)
async def delete_storage_file_route(request: StorageDeleteFileRequest) -> dict:
    """
    Delete a storage file. Server Owner only.
    """
    require_server_owner(request.auth_token)

    if await _is_file_protected(request.file_url):
        raise exceptions.HTTPException(
            status_code=403,
            detail="Cannot delete this file as it is currently used as a user or server avatar/banner.",
        )

    relative_path = _resolve_storage_relative_path(request.file_url)
    if not relative_path:
        raise exceptions.HTTPException(status_code=404, detail="File not found")

    file_hash = _file_hash_from_relative_path(relative_path)
    if not file_hash:
        try:
            content = await api_initializer.storage_manager.read_file_content(
                relative_path
            )
            file_hash = api_initializer.storage_manager.compute_file_hash(content)
        except Exception:
            file_hash = None

    deleted = await api_initializer.storage_manager.delete_file(relative_path)
    if not deleted:
        raise exceptions.HTTPException(status_code=404, detail="File not found")

    if file_hash:
        _remove_file_metadata(file_hash)

    return {
        "status_code": 200,
        "message": "File deleted successfully",
        "file_url": request.file_url,
    }


@router.post("/api/v1/storage/cleanup-orphaned", status_code=200)
async def cleanup_orphaned_storage_files_route(
    request: CleanupOrphanedRequest,
) -> dict:
    """
    Remove unreferenced files from storage. Server Owner only.
    """
    require_server_owner(request.auth_token)

    storage_root = _get_storage_root()
    if not storage_root.exists():
        return {
            "status_code": 200,
            "message": "Storage path does not exist",
            "subdirectory": request.subdirectory,
            "deleted_count": 0,
        }

    existing_dirs = sorted(
        item.name for item in storage_root.iterdir() if item.is_dir()
    )
    requested = request.subdirectory or "all"
    target_dirs = [d for d in _target_directories(requested, existing_dirs) if d in existing_dirs]

    referenced_paths = _load_referenced_paths()
    deleted_count = 0

    for directory in target_dirs:
        sub_dir = storage_root / directory
        for file_path in sub_dir.glob("*"):
            if not file_path.is_file():
                continue

            relative_path = str(file_path.relative_to(storage_root)).replace("\\", "/")
            if relative_path in referenced_paths:
                continue

            public_url = _build_public_storage_url(relative_path)
            if await _is_file_protected(public_url):
                continue

            if await api_initializer.storage_manager.delete_file(relative_path):
                deleted_count += 1

    return {
        "status_code": 200,
        "message": "Orphaned files cleanup completed successfully",
        "subdirectory": request.subdirectory,
        "deleted_count": deleted_count,
    }


@router.get("/api/v1/storage/file/{file_path:path}", status_code=200)
async def serve_storage_file_route(
    file_path: str, auth_token: str | None = None
) -> responses.Response:
    """
    Serve a storage file by relative path with optional authentication.
    """
    normalized_path = file_path.strip().lstrip("/")
    if ".." in Path(normalized_path).parts:
        raise exceptions.HTTPException(status_code=400, detail="Invalid file path")

    if auth_token:
        try:
            from pufferblow.api.dependencies import get_current_user

            get_current_user(auth_token)
        except Exception:
            raise exceptions.HTTPException(
                status_code=403, detail="Invalid authentication token"
            )

    try:
        content = await api_initializer.storage_manager.read_file_content(normalized_path)
    except exceptions.HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Failed to read storage file {normalized_path}: {exc}")
        raise exceptions.HTTPException(status_code=404, detail="File not found")

    content_type, _ = mimetypes.guess_type(normalized_path)
    if not content_type:
        content_type = "application/octet-stream"

    filename = Path(normalized_path).name
    return responses.Response(
        content=content,
        media_type=content_type,
        headers={"Content-Disposition": f"inline; filename={filename}"},
    )


@router.get("/storage/{file_hash}", status_code=200)
async def serve_file_by_hash(file_hash: str) -> responses.Response:
    """
    Serve a file by its content hash.
    """
    file_object = api_initializer.database_handler.get_file_object_by_hash(file_hash)
    if not file_object:
        raise exceptions.HTTPException(status_code=404, detail="File not found")

    try:
        content = await api_initializer.storage_manager.read_file_content(
            file_object.file_path
        )
    except exceptions.HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Failed to read hash-addressed file {file_hash}: {exc}")
        raise exceptions.HTTPException(status_code=404, detail="File not found")

    content_type, _ = mimetypes.guess_type(file_object.file_path)
    if not content_type:
        content_type = file_object.mime_type or "application/octet-stream"

    return responses.Response(
        content=content,
        media_type=content_type,
        headers={"Content-Disposition": f"inline; filename={Path(file_object.file_path).name}"},
    )
