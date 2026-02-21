"""Shared user presence status semantics and normalization helpers."""

from __future__ import annotations

from typing import Final


SUPPORTED_USER_STATUSES: Final[tuple[str, ...]] = (
    "online",
    "idle",
    "afk",
    "dnd",
    "offline",
)

_STATUS_ALIASES: Final[dict[str, str]] = {
    "away": "afk",
    "inactive": "offline",
    "invisible": "offline",
}


def normalize_user_status(status: str) -> str:
    """
    Normalize a raw status value to a canonical status.

    Args:
        status (str): Raw user status.

    Returns:
        str: Canonical status.

    Raises:
        ValueError: If status is empty or unsupported.
    """
    if status is None:
        raise ValueError("Status is required.")

    normalized = status.strip().lower()
    if not normalized:
        raise ValueError("Status is required.")

    normalized = _STATUS_ALIASES.get(normalized, normalized)
    if normalized not in SUPPORTED_USER_STATUSES:
        supported = ", ".join(SUPPORTED_USER_STATUSES)
        raise ValueError(f"Unsupported status '{status}'. Supported values: {supported}")

    return normalized


def is_supported_user_status(status: str) -> bool:
    """
    Return whether a status value is supported.
    """
    try:
        normalize_user_status(status)
        return True
    except ValueError:
        return False
