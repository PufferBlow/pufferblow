"""What the owner may choose about how the server looks, and the rules for it.

A server is painted the way a person is (see ``profile_settings``): everything is a choice from a short
list, never free text or free colours, so any client can draw it and it can never be made unreadable.
Each setting may be null, meaning "use the one derived from the server's id", which is what every client
shows until the owner chooses. The settings live in one JSON column (``server.profile_settings``), so a
new option needs no new column, and unknown keys are refused rather than stored.
"""

from __future__ import annotations

from typing import Any

from pufferblow.api.utils.profile_settings import BANNER_PATTERNS, TONES

# How the icon is drawn before the server has a picture: its initials, a fish peeking in, a bubble, a school.
ICON_STYLES = ("initials", "crop", "bubble", "school")

WELCOME_MESSAGE_MAX = 500

DEFAULT_SERVER_LOOK: dict[str, Any] = {
    "icon_style": None,
    "tone": None,
    "tone2": None,
    "banner_pattern": None,
}

_CHOICES: dict[str, tuple[str, ...]] = {
    "icon_style": ICON_STYLES,
    "tone": TONES,
    "tone2": TONES,
    "banner_pattern": BANNER_PATTERNS,
}


class ServerLookError(ValueError):
    """A setting that is not allowed. ``field`` names it for the error's details."""

    def __init__(self, field: str, message: str) -> None:
        super().__init__(message)
        self.field = field


def effective_server_look(stored: dict[str, Any] | None) -> dict[str, Any]:
    """The look the server has, with the derived default for anything the owner never chose."""
    merged = dict(DEFAULT_SERVER_LOOK)
    if isinstance(stored, dict):
        merged.update({k: v for k, v in stored.items() if k in merged})
    return merged


def merge_server_look(current: dict[str, Any] | None, changes: Any) -> dict[str, Any]:
    """Apply a partial update, validating every part of it.

    Only the keys sent change; null puts a setting back to the derived default. Raises
    :class:`ServerLookError` for anything unknown or out of range, in which case nothing is written.
    """
    if not isinstance(changes, dict):
        raise ServerLookError("look", "look must be an object")

    result = effective_server_look(current)
    for key, value in changes.items():
        choices = _CHOICES.get(key)
        if choices is None:
            raise ServerLookError(key, f"{key} is not a server look setting; use any of {sorted(_CHOICES)}")
        if value is None:
            result[key] = None
        elif isinstance(value, str) and value in choices:
            result[key] = value
        else:
            raise ServerLookError(key, f"{key} must be one of {list(choices)} or null")
    return result
