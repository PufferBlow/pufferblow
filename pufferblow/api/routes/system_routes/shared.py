"""Shared helpers for system route modules."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from fastapi import Form, HTTPException
from loguru import logger
from pydantic import BaseModel, Field

from pufferblow.api.database.tables.activity_audit import ActivityAudit
from pufferblow.api.schemas import UploadAuthForm
from pufferblow.api.utils.extract_user_id import extract_user_id
from pufferblow.core.bootstrap import api_initializer


class ChartRequest(BaseModel):
    """Request body for chart endpoints."""

    auth_token: str = Field(min_length=1)
    period: str | None = Field(
        default=None,
        description="Time period (daily, weekly, monthly, 24h, 7d)",
    )


class UserStatusChartRequest(BaseModel):
    """Request body for user status chart endpoint."""

    auth_token: str = Field(min_length=1)


class RecentActivityRequest(BaseModel):
    """Request body for recent activity endpoint."""

    auth_token: str = Field(min_length=1)
    limit: int = Field(default=10, ge=1, le=100)


class ServerLogsRequest(BaseModel):
    """Request body for server logs endpoint."""

    auth_token: str = Field(min_length=1)
    lines: int = Field(default=50, ge=1, le=1000)
    search: str | None = Field(default=None)
    level: str | None = Field(
        default=None,
        description="Filter by log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)",
    )


@dataclass(slots=True)
class ServerState:
    """Current server row plus settings row if present."""

    server: object | None
    settings: object | None


async def parse_upload_auth_form(
    auth_token: str = Form(..., description="User's authentication token"),
) -> UploadAuthForm:
    """Parse upload auth form."""
    return UploadAuthForm(auth_token=auth_token)


def extract_user(auth_token: str) -> str:
    """Extract current user id from auth token."""
    return extract_user_id(auth_token=auth_token)


def require_component(component: str):
    """Return a loaded initializer component or raise a controlled error."""
    if not api_initializer.is_ready(component):
        raise HTTPException(
            status_code=503,
            detail=f"Server component '{component}' is not initialized.",
        )

    instance = getattr(api_initializer, component, None)
    if instance is None:
        raise HTTPException(
            status_code=503,
            detail=f"Server component '{component}' is unavailable.",
        )
    return instance


def get_server_state() -> ServerState:
    """Return server row and settings row if available."""
    database_handler = require_component("database_handler")
    try:
        server = database_handler.get_server()
    except Exception:
        server = None

    try:
        settings = database_handler.get_server_settings()
    except Exception:
        settings = None

    return ServerState(server=server, settings=settings)


def require_server_owner(auth_token: str) -> str:
    """Ensure current user is the server owner."""
    user_id = extract_user(auth_token)
    user_manager = require_component("user_manager")
    if not user_manager.is_server_owner(user_id=user_id):
        raise HTTPException(
            status_code=403,
            detail="Access forbidden. Only the server owner can perform this action.",
        )
    return user_id


def require_admin(auth_token: str, *, allow_owner: bool = False) -> str:
    """Ensure current user is an admin, optionally allowing the owner."""
    user_id = extract_user(auth_token)
    user_manager = require_component("user_manager")
    if user_manager.is_admin(user_id=user_id):
        return user_id
    if allow_owner and user_manager.is_server_owner(user_id=user_id):
        return user_id
    raise HTTPException(
        status_code=403,
        detail="Access forbidden. Only administrators can perform this action.",
    )


def require_admin_or_owner(auth_token: str) -> str:
    """Ensure current user is admin or owner."""
    user_id = extract_user(auth_token)
    user_manager = require_component("user_manager")
    if user_manager.is_admin(user_id=user_id) or user_manager.is_server_owner(
        user_id=user_id
    ):
        return user_id
    raise HTTPException(
        status_code=403,
        detail="Access forbidden. Only administrators can perform this action.",
    )


def require_privilege(auth_token: str, privilege_id: str) -> str:
    """Ensure current user has a resolved instance privilege."""
    user_id = extract_user(auth_token)
    user_manager = require_component("user_manager")
    if user_manager.has_privilege(user_id=user_id, privilege_id=privilege_id):
        return user_id
    raise HTTPException(
        status_code=403,
        detail=f"Access forbidden. Missing required privilege: {privilege_id}.",
    )


def log_activity(
    *,
    activity_type: str,
    user_id: str | None,
    title: str,
    description: str,
    metadata: dict | None = None,
) -> None:
    """Best-effort activity audit logging."""
    try:
        database_handler = require_component("database_handler")
        database_handler.create_activity_audit_entry(
            ActivityAudit(
                activity_id=str(uuid.uuid4()),
                activity_type=activity_type,
                user_id=user_id,
                title=title,
                description=description,
                metadata_json=json.dumps(metadata or {}),
            )
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("Failed to create activity audit entry: {}", exc)


def _is_hash(value: str) -> bool:
    """Check if a string looks like a SHA-256 hash."""
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value.lower())


def extract_storage_hash(storage_url: str | None) -> str | None:
    """Extract hash from canonical storage URL (`/storage/<hash>`)."""
    if not storage_url or api_initializer.config is None:
        return None

    path = urlparse(storage_url).path if "://" in storage_url else storage_url
    base = api_initializer.config.STORAGE_BASE_URL.rstrip("/")
    if not path.startswith(f"{base}/"):
        return None

    suffix = path[len(base) + 1 :]
    if "/" in suffix or not _is_hash(suffix):
        return None
    return suffix


def resolve_storage_relative_path(storage_url: str | None) -> str | None:
    """Resolve relative storage path from hash URL or direct storage file URL."""
    if not storage_url or api_initializer.config is None:
        return None

    path = urlparse(storage_url).path if "://" in storage_url else storage_url
    base = api_initializer.config.STORAGE_BASE_URL.rstrip("/")

    file_hash = extract_storage_hash(path)
    if file_hash:
        database_handler = require_component("database_handler")
        file_object = database_handler.get_file_object_by_hash(file_hash)
        return file_object.file_path if file_object else None

    if path.startswith("/api/v1/storage/file/"):
        return path.replace("/api/v1/storage/file/", "", 1).lstrip("/") or None

    if path.startswith(f"{base}/"):
        suffix = path[len(base) + 1 :]
        if "/" in suffix:
            return suffix

    return None


async def delete_previous_storage_file(storage_url: str | None) -> None:
    """Best-effort cleanup for previously assigned server media file."""
    relative_path = resolve_storage_relative_path(storage_url)
    if not relative_path:
        return

    storage_manager = require_component("storage_manager")
    try:
        await storage_manager.delete_file(relative_path)
        logger.info("Deleted previous server media file: {}", relative_path)
    except Exception as exc:
        logger.warning(
            "Failed to delete previous storage file {}: {}",
            storage_url,
            exc,
        )


def create_server_file_reference(file_hash: str, reference_type: str) -> None:
    """Create a storage reference entry for server avatar/banner assets."""
    database_handler = require_component("database_handler")
    try:
        database_handler.create_file_reference(
            reference_id=f"{reference_type}_{uuid.uuid4()}",
            file_hash=file_hash,
            reference_type=reference_type,
            reference_entity_id="server",
        )
    except Exception as exc:
        logger.warning(
            "Failed to create file reference {} for hash {}: {}",
            reference_type,
            file_hash,
            exc,
        )


def list_log_candidates(log_path: str | None) -> tuple[list[Path], list[str]]:
    """Return available log files plus searched path labels."""
    searched_paths: list[str] = []
    log_files: list[Path] = []

    if log_path:
        log_dir = Path(log_path).parent
        searched_paths.append(str(log_dir))
        if log_dir.exists():
            for pattern in ("*.log", "*.txt", "pufferblow*.log", "server*.log"):
                log_files.extend(log_dir.glob(pattern))

    fallback_paths = [
        Path("/var/log/pufferblow.log"),
        Path("/var/log/pufferblow/server.log"),
        Path("./logs/pufferblow.log"),
        Path("./logs/server.log"),
    ]
    for path in fallback_paths:
        searched_paths.append(str(path))
        if path.exists():
            log_files.append(path)

    deduped: list[Path] = []
    seen: set[str] = set()
    for path in log_files:
        key = str(path.resolve()) if path.exists() else str(path)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(path)

    return deduped, searched_paths
