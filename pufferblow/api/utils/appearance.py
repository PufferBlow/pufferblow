"""Deterministic appearance defaults for users and servers.

When a new user or server is created we hand out an accent color and
an identicon seed up front, so the UI has something to render before
the owner uploads anything. The accent color is derived from the
entity's stable id (user_id / server_id) so the same user always gets
the same default, and so two users on the same instance reliably get
different colors instead of collisions.

The 16-color palette below is sampled from Tailwind's 500/600 weights
and tuned for readability on both light and dark backgrounds. It is
deliberately small: a curated palette beats a continuous hue picker
for "looks intentional" — every color in the palette has been checked
against the rest of the UI tokens.

Callers can override at any time via the appearance endpoints. This
helper is for the initial assignment + the "shuffle" action.
"""

from __future__ import annotations

import hashlib
import secrets

# Curated 16-color palette. Order matters for stability — if you ever
# re-arrange this list every existing user's default accent shifts.
# Append to the END if you grow the palette.
ACCENT_COLOR_PALETTE: tuple[str, ...] = (
    "#ef4444",  # red
    "#f97316",  # orange
    "#f59e0b",  # amber
    "#eab308",  # yellow
    "#84cc16",  # lime
    "#22c55e",  # green
    "#10b981",  # emerald
    "#14b8a6",  # teal
    "#06b6d4",  # cyan
    "#0ea5e9",  # sky
    "#3b82f6",  # blue
    "#6366f1",  # indigo
    "#8b5cf6",  # violet
    "#a855f7",  # purple
    "#d946ef",  # fuchsia
    "#ec4899",  # pink
)


def derive_accent_color(seed: str) -> str:
    """Return a stable hex color from the palette for ``seed``.

    Uses SHA-256 of the seed so a tiny change in input (e.g. one char
    difference in user_id) reliably picks a different color. We don't
    use ``hash()`` because Python hashes salt themselves per-process,
    which would mean a user gets a different default every time the
    server restarts — bad UX.
    """
    if not seed:
        # Fall back to the first palette entry rather than raise.
        # A creation path that forgets to supply an id is already a
        # bug; pinning to one color makes it visible without crashing.
        return ACCENT_COLOR_PALETTE[0]
    digest = hashlib.sha256(seed.encode("utf-8")).digest()
    index = digest[0] % len(ACCENT_COLOR_PALETTE)
    return ACCENT_COLOR_PALETTE[index]


def generate_shuffle_seed() -> str:
    """Return a fresh random seed for the 'shuffle my identicon' action.

    16 bytes hex = 32 chars, plenty of entropy for an identicon
    parameter and short enough to fit comfortably in a URL.
    """
    return secrets.token_hex(16)


# Accepted values for the *_kind columns. Centralized here so the
# appearance endpoints validate against the same set the column
# constraints assume.
VALID_AVATAR_KINDS = frozenset({"identicon", "image"})
VALID_BANNER_KINDS = frozenset({"solid", "image"})


_HEX_COLOR_LEN = 7  # "#RRGGBB"


def is_valid_hex_color(value: str | None) -> bool:
    """True iff ``value`` is a "#RRGGBB" hex color (case-insensitive).

    We deliberately reject the 4-char short form and 9-char alpha
    form. The UI emits long form; allowing the others creates a
    surface where backups round-trip and break equality.
    """
    if not isinstance(value, str):
        return False
    if len(value) != _HEX_COLOR_LEN or value[0] != "#":
        return False
    try:
        int(value[1:], 16)
    except ValueError:
        return False
    return True
