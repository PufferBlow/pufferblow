"""What a person may customise on their profile, and the rules for it.

The profile is the one surface a person is allowed to paint: an avatar frame, a colour (or two), a
card theme, a banner pattern, a name style, which sections show on the card, and whether the avatar
moves. Everything is a choice from a short list, never free text or free colours, so a profile can be
rendered by any client and can never be made unreadable: the client mixes the chosen colour into a
dark card at a fixed, low strength and the person never picks the text colour.

The settings live in one JSON column (``users.profile_settings``) so a new option does not need a new
column. Unknown keys are refused rather than stored, which keeps the column from becoming a place to
put arbitrary data.
"""

from __future__ import annotations

from typing import Any

# The six identity colours (see the design language). Names, not hex values: a client maps them.
TONES = ("brass", "coral", "rose", "violet", "sky", "sage")
EXPRESSIONS = ("default", "happy", "wink", "sleepy", "surprised", "grumpy")
FRAMES = ("none", "ring", "spines", "bubbles")
# mono: no tint. tinted: the colour mixed into the card. duo: the colour fading into the second one.
CARD_THEMES = ("mono", "tinted", "duo")
# The four patterns, or "duo": a gradient between the two colours. An uploaded banner is banner_kind "image".
BANNER_PATTERNS = ("ripple", "burst", "halftone", "crowd", "duo")
NAME_FONTS = ("marcellus", "barlow", "condensed")
MOTIONS = ("puff", "still")
SECTIONS = ("play", "mains", "accounts", "badges")

PRONOUNS_MAX = 40
CUSTOM_STATUS_MAX = 60
ABOUT_MAX = 190

DEFAULT_PROFILE_SETTINGS: dict[str, Any] = {
    "expression": None,
    "frame": "none",
    "tone": None,
    "tone2": None,
    "card_theme": "mono",
    "banner_pattern": None,
    "name_font": "barlow",
    "motion": "puff",
    "sections": {"play": True, "mains": True, "accounts": False, "badges": True},
}

_CHOICES: dict[str, tuple[str, ...]] = {
    "expression": EXPRESSIONS,
    "frame": FRAMES,
    "tone": TONES,
    "tone2": TONES,
    "card_theme": CARD_THEMES,
    "banner_pattern": BANNER_PATTERNS,
    "name_font": NAME_FONTS,
    "motion": MOTIONS,
}
# These may be null: "use the face/colour/pattern derived from my handle".
_NULLABLE = {"expression", "tone", "tone2", "banner_pattern"}


class ProfileSettingsError(ValueError):
    """A setting that is not allowed. ``field`` names it for the error's details."""

    def __init__(self, field: str, message: str) -> None:
        super().__init__(message)
        self.field = field


def effective_profile_settings(stored: dict[str, Any] | None) -> dict[str, Any]:
    """The settings a person has, with defaults for anything they never chose."""
    merged = {k: (dict(v) if isinstance(v, dict) else v) for k, v in DEFAULT_PROFILE_SETTINGS.items()}
    if not isinstance(stored, dict):
        return merged
    for key, value in stored.items():
        if key == "sections" and isinstance(value, dict):
            merged["sections"].update({k: bool(v) for k, v in value.items() if k in SECTIONS})
        elif key in merged and key != "sections":
            merged[key] = value
    return merged


def merge_profile_settings(current: dict[str, Any] | None, changes: Any) -> dict[str, Any]:
    """Apply a partial update to the stored settings, validating every part of it.

    ``changes`` is a (partial) settings object: only the keys sent change, and ``sections`` is merged
    one section at a time. Raises :class:`ProfileSettingsError` for anything unknown or out of range,
    in which case nothing should be written.
    """
    if not isinstance(changes, dict):
        raise ProfileSettingsError("profile_settings", "profile_settings must be an object")

    result = effective_profile_settings(current)
    for key, value in changes.items():
        if key == "sections":
            if not isinstance(value, dict):
                raise ProfileSettingsError("sections", "sections must be an object of true/false values")
            for name, shown in value.items():
                if name not in SECTIONS:
                    raise ProfileSettingsError(f"sections.{name}", f"sections.{name} is not a section; use one of {list(SECTIONS)}")
                if not isinstance(shown, bool):
                    raise ProfileSettingsError(f"sections.{name}", f"sections.{name} must be true or false")
                result["sections"][name] = shown
            continue
        choices = _CHOICES.get(key)
        if choices is None:
            raise ProfileSettingsError(key, f"{key} is not a profile setting; use any of {sorted([*_CHOICES, 'sections'])}")
        if value is None and key in _NULLABLE:
            result[key] = None
        elif isinstance(value, str) and value in choices:
            result[key] = value
        else:
            raise ProfileSettingsError(key, f"{key} must be one of {list(choices)}" + (" or null" if key in _NULLABLE else ""))
    return result


def check_text_length(field: str, value: str, limit: int) -> str:
    """The value, trimmed, or a :class:`ProfileSettingsError` if it is longer than ``limit`` characters."""
    text = value.strip()
    if len(text) > limit:
        raise ProfileSettingsError(field, f"{field} can be at most {limit} characters")
    return text
