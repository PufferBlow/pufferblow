"""Role badges: the small mark after a person's name that says what they do in a space.

The design (``spines/specs/role-badges.html``) keeps every choice to a short list, so any client can
draw a badge and none can pass for another:

* **tier** is the shape and says who gave the role. ``staff`` (spined) is for roles that can moderate,
  ``community`` (rounded square) is for everything a space invents, ``system`` (circle) is given by
  Pufferblow and never by a space, so it can neither be chosen nor edited.
* **tone** is one of the six identity colours, white or grey.
* **glyph** is one of the built-in drawings, or ``image`` with an uploaded picture's address.

A badge is stored on the role as one JSON object (``roles.badge``); null means the role has none, except
that the built-in Owner, Admin and Moderator roles are shown with theirs without storing anything.
"""

from __future__ import annotations

import io
from typing import Any

TIERS = ("staff", "community", "system")
# What a space may choose: the system tier is reserved.
CHOOSABLE_TIERS = ("staff", "community")
TONES = ("brass", "coral", "rose", "violet", "sky", "sage", "white", "grey")
GLYPHS = (
    "crown", "key", "shield", "lifebuoy", "target", "star", "broadcast", "brush", "code", "heart", "trophy",
    "flame", "bot", "check", "bubbles", "globe", "music", "film", "gamepad", "mic",
)
IMAGE_GLYPH = "image"

# Roles with any of these may moderate, which is what the spined staff shape stands for.
MODERATION_PRIVILEGES = frozenset({"ban_users", "mute_users", "moderate_content"})

# The most roles in one space that can carry a badge.
MAX_BADGED_ROLES = 50

# An uploaded badge picture: a square PNG, small.
IMAGE_SIZE = 128
IMAGE_MAX_BYTES = 256 * 1024
IMAGE_URL_PREFIX = "/storage/"

BUILT_IN_BADGES: dict[str, dict[str, Any]] = {
    "owner": {"tier": "staff", "tone": "brass", "glyph": "crown"},
    "moderator": {"tier": "staff", "tone": "sky", "glyph": "shield"},
}


class RoleBadgeError(ValueError):
    """A badge that is not allowed. ``field`` names the part for the error's details."""

    def __init__(self, field: str, message: str) -> None:
        super().__init__(message)
        self.field = field


def effective_badge(role_id: str, stored: Any) -> dict[str, Any] | None:
    """The badge a role is shown with: the one stored, else the built-in one for its id, else none."""
    if isinstance(stored, dict) and stored:
        return {key: stored.get(key) for key in ("tier", "tone", "glyph", "image_url") if stored.get(key) is not None}
    return dict(BUILT_IN_BADGES[role_id]) if role_id in BUILT_IN_BADGES else None


def can_moderate(privileges_ids: list[str] | set[str] | tuple[str, ...]) -> bool:
    return bool(MODERATION_PRIVILEGES & set(privileges_ids))


def check_badge(raw: Any, privileges_ids: list[str]) -> dict[str, Any]:
    """The badge to store, or ``RoleBadgeError`` naming what is wrong.

    The staff tier needs a moderation privilege on the role, so a custom community role cannot be made to
    look like a moderator.
    """
    if not isinstance(raw, dict):
        raise RoleBadgeError("badge", "A badge is an object with a tier, a tone and a glyph.")
    unknown = sorted(set(raw) - {"tier", "tone", "glyph", "image_url"})
    if unknown:
        raise RoleBadgeError(unknown[0], f"'{unknown[0]}' is not a badge setting.")

    tier = raw.get("tier", "community")
    if tier == "system":
        raise RoleBadgeError("tier", "The system tier is given by Pufferblow and cannot be chosen.")
    if tier not in CHOOSABLE_TIERS:
        raise RoleBadgeError("tier", f"tier must be one of {list(CHOOSABLE_TIERS)}.")
    if tier == "staff" and not can_moderate(privileges_ids):
        raise RoleBadgeError("tier", "The staff shape is for roles that can moderate: give the role a moderation privilege first.")

    tone = raw.get("tone")
    if tone not in TONES:
        raise RoleBadgeError("tone", f"tone must be one of {list(TONES)}.")

    glyph = raw.get("glyph")
    if glyph not in (*GLYPHS, IMAGE_GLYPH):
        raise RoleBadgeError("glyph", f"glyph must be one of {[*GLYPHS, IMAGE_GLYPH]}.")

    badge: dict[str, Any] = {"tier": tier, "tone": tone, "glyph": glyph}
    if glyph == IMAGE_GLYPH:
        url = raw.get("image_url")
        if not isinstance(url, str) or not url.startswith(IMAGE_URL_PREFIX) or len(url) > 200 or ".." in url:
            raise RoleBadgeError("image_url", "An image badge needs the address of an uploaded badge picture.")
        badge["image_url"] = url
    elif raw.get("image_url") is not None:
        raise RoleBadgeError("image_url", "Only an image badge has an image address.")
    return badge


def check_badge_image(content: bytes) -> None:
    """Refuse anything but a 128 x 128 PNG under 256 KB, with ``RoleBadgeError`` saying why."""
    if len(content) == 0:
        raise RoleBadgeError("file", "The file is empty.")
    if len(content) > IMAGE_MAX_BYTES:
        raise RoleBadgeError("file", f"The picture is larger than {IMAGE_MAX_BYTES // 1024} KB.")
    if not content.startswith(b"\x89PNG\r\n\x1a\n"):
        raise RoleBadgeError("file", "A badge picture must be a PNG.")
    try:
        from PIL import Image

        with Image.open(io.BytesIO(content)) as image:
            image.verify()
        with Image.open(io.BytesIO(content)) as image:
            size = image.size
    except Exception as exc:  # a damaged picture is the person's to fix
        raise RoleBadgeError("file", "That PNG could not be read.") from exc
    if size != (IMAGE_SIZE, IMAGE_SIZE):
        raise RoleBadgeError("file", f"A badge picture must be {IMAGE_SIZE} × {IMAGE_SIZE}; this one is {size[0]} × {size[1]}.")
