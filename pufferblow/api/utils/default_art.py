"""Default avatars and banners: real files the server hosts, assigned from an id.

Every user and server gets a default avatar and banner at creation, drawn from the brand's puffer
set (12 tones x 6 expressions). They are ordinary image files under ``/assets/avatars/`` and
``/assets/banners/`` (SVG, plus a PNG rendition of each for clients that cannot draw SVG), and the
chosen path is written into ``avatar_url`` / ``banner_url``. So any client, official or not, shows
the same picture by following the URL it is given; nothing is drawn client-side from a seed.

The pick is deterministic: the same id always gets the same art, and the banner shares the avatar's
tone so the two go together. ``TONES`` and ``EXPRESSIONS`` are ordered on purpose; reordering them
changes everyone's default, so append only. ``scripts/assets/build_default_art.py`` produces the
files from the brand sheet.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

ASSET_ROOT = Path(__file__).resolve().parents[2] / "assets" / "default-art"

#: Order is part of the contract (see module docstring).
TONES: tuple[str, ...] = ("ink", "graphite", "slate", "ash", "silver", "paper", "brass", "coral", "rose", "violet", "sky", "sage")
EXPRESSIONS: tuple[str, ...] = ("default", "happy", "wink", "sleepy", "surprised", "grumpy")

AVATAR_URL_PREFIX = "/assets/avatars/"
BANNER_URL_PREFIX = "/assets/banners/"
_FORMATS = ("svg", "png")


def _pick(seed: str) -> tuple[str, str, str]:
    """(tone, avatar expression, banner expression) for ``seed``."""
    digest = hashlib.sha256((seed or "").encode("utf-8")).digest()
    return TONES[digest[0] % len(TONES)], EXPRESSIONS[digest[1] % len(EXPRESSIONS)], EXPRESSIONS[digest[2] % len(EXPRESSIONS)]


def avatar_name(seed: str) -> str:
    tone, expression, _ = _pick(seed)
    return f"pb-avatar-{expression}-{tone}"


def banner_name(seed: str) -> str:
    tone, _, expression = _pick(seed)
    return f"pb-banner-{expression}-{tone}"


def default_avatar_url(seed: str, fmt: str = "svg") -> str:
    """Server-relative URL of the default avatar for ``seed`` (clients join it to the instance origin)."""
    return f"{AVATAR_URL_PREFIX}{avatar_name(seed)}.{fmt}"


def default_banner_url(seed: str, fmt: str = "svg") -> str:
    return f"{BANNER_URL_PREFIX}{banner_name(seed)}.{fmt}"


def is_default_art_url(url: str | None) -> bool:
    """Whether ``url`` points at one of the hosted default images (as opposed to an upload)."""
    if not url:
        return False
    path = url.split("?", 1)[0].split("#", 1)[0]
    marker = path.find("/assets/")
    return marker != -1 and path[marker:].startswith((AVATAR_URL_PREFIX, BANNER_URL_PREFIX))


def asset_file(folder: str, filename: str) -> Path | None:
    """The file behind ``/assets/<folder>/<filename>``, or None. Only names the set contains resolve."""
    if folder not in ("avatars", "banners") or "/" in filename or "\\" in filename or ".." in filename:
        return None
    stem, _, suffix = filename.rpartition(".")
    if suffix not in _FORMATS or not stem:
        return None
    path = ASSET_ROOT / folder / filename
    return path if path.is_file() else None


@dataclass(frozen=True)
class AppearancePlan:
    """What to write for an appearance change: the extra column values, beyond the kinds and seed."""

    avatar_kind: str | None
    banner_kind: str | None
    avatar_url: str | None
    banner_url: str | None


def plan_appearance_update(
    *,
    stable_id: str,
    current_seed: str | None,
    current_avatar_url: str | None,
    current_banner_url: str | None,
    avatar_kind: str | None,
    banner_kind: str | None,
    new_seed: str | None,
) -> AppearancePlan:
    """Work out the URLs that go with a requested appearance change.

    The URLs always match the kinds, so a client that only reads ``avatar_url`` is never out of step:

    * ``avatar_kind == "identicon"`` (the default art): ``avatar_url`` is the default avatar for the
      seed. Choosing it again, or shuffling the seed, repaints it.
    * ``avatar_kind == "image"`` is only honoured while there is an upload to go back to; otherwise
      the default art stays.
    * ``banner_kind == "default"``: ``banner_url`` is the default banner for the seed.
    * ``banner_kind == "solid"``: no banner image (an empty ``banner_url``; the accent colour shows).

    ``""`` means "clear"; ``None`` means "leave as it is".
    """
    seed = new_seed or current_seed or stable_id
    has_upload = bool(current_avatar_url) and not is_default_art_url(current_avatar_url)
    has_banner_upload = bool(current_banner_url) and not is_default_art_url(current_banner_url)

    out_avatar_kind = avatar_kind
    avatar_url: str | None = None
    if avatar_kind == "image" and not has_upload:
        out_avatar_kind = None  # nothing to switch back to
    elif avatar_kind == "identicon" or (new_seed and not has_upload):
        avatar_url = default_avatar_url(seed)

    out_banner_kind = banner_kind
    banner_url: str | None = None
    if banner_kind == "image" and not has_banner_upload:
        out_banner_kind = None
    elif banner_kind == "default":
        banner_url = default_banner_url(seed)
    elif banner_kind == "solid":
        banner_url = ""
    elif new_seed and is_default_art_url(current_banner_url):
        banner_url = default_banner_url(seed)

    return AppearancePlan(out_avatar_kind, out_banner_kind, avatar_url, banner_url)
