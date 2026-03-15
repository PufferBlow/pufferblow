"""Helpers for canonical storage path and URL handling."""

from __future__ import annotations

from pathlib import Path, PurePosixPath
from urllib.parse import urlparse


def is_sha256_hash(value: str) -> bool:
    """Return whether a string looks like a SHA-256 hash."""
    normalized = (value or "").strip().lower()
    return len(normalized) == 64 and all(ch in "0123456789abcdef" for ch in normalized)


def normalize_storage_relative_path(path: str) -> str:
    """Normalize a relative storage path and reject traversal attempts."""
    raw_path = (path or "").strip().replace("\\", "/")
    if not raw_path:
        raise ValueError("Storage path cannot be empty")

    posix_path = PurePosixPath(raw_path.lstrip("/"))
    parts = list(posix_path.parts)
    if not parts:
        raise ValueError("Storage path cannot be empty")
    if any(part in {"..", ""} for part in parts):
        raise ValueError("Storage path contains invalid traversal segments")
    if parts[0].endswith(":"):
        raise ValueError("Storage path must be relative")

    return "/".join(parts)


def resolve_local_storage_path(base_path: Path, relative_path: str) -> Path:
    """Resolve a normalized relative storage path under a storage root."""
    normalized = normalize_storage_relative_path(relative_path)
    base_resolved = base_path.expanduser().resolve()
    candidate = (base_resolved / normalized).resolve()
    if candidate != base_resolved and base_resolved not in candidate.parents:
        raise ValueError("Resolved storage path escapes the configured storage root")
    return candidate


def is_local_media_url(file_url: str | None, *, api_host: str, api_port: int) -> bool:
    """Return whether a media URL should be treated as local to this instance."""
    if not file_url:
        return False

    parsed = urlparse(file_url)
    if not parsed.scheme or not parsed.netloc:
        return True

    parsed_host = (parsed.hostname or "").strip().lower()
    parsed_port = parsed.port
    scheme = (parsed.scheme or "").lower()
    default_port = 443 if scheme == "https" else 80
    normalized_port = parsed_port or default_port

    configured_host = (api_host or "").strip().lower()
    local_aliases = {configured_host}
    if configured_host in {"127.0.0.1", "0.0.0.0", "localhost", "::1"}:
        local_aliases.update({"127.0.0.1", "localhost", "::1", "0.0.0.0"})

    return parsed_host in local_aliases and normalized_port == int(api_port)


def extract_local_media_path(
    file_url: str | None,
    *,
    api_host: str,
    api_port: int,
) -> str | None:
    """Extract the path component from a local or relative media URL."""
    if not file_url:
        return None
    if not is_local_media_url(file_url, api_host=api_host, api_port=api_port):
        return None

    if "://" in file_url:
        return urlparse(file_url).path
    return file_url
