"""Scrub credentials from log text.

Access logs print the full request line, and this API takes tokens and passwords in
query strings (``?auth_token=...``, ``/ws?auth_token=...``, ``/users/signin?password=...``).
Anything that reaches the logs passes through :func:`redact` first, so a leaked log file
or a shared terminal capture does not hand out working sessions.
"""

from __future__ import annotations

import re

REDACTED = "[REDACTED]"

_SENSITIVE_KEYS = (
    "auth_token",
    "refresh_token",
    "access_token",
    "token",
    "password",
    "old_password",
    "new_password",
    "confirm_password",
    "secret",
    "api_key",
    "apikey",
    "sse_key",
    "authorization",
    "signature",
)

# key=value in a query string, form body or key=value log field.
_PARAM = re.compile(r"(?i)\b(" + "|".join(_SENSITIVE_KEYS) + r")=([^&\s\"'<>#]+)")
# "Authorization: Bearer xxx"
_BEARER = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}")
# A JSON Web Token anywhere in the text (these are the session tokens).
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}")
# Bot tokens: pbb_<prefix>.<secret>
_BOT_TOKEN = re.compile(r"\bpbb_[0-9a-f]{6,}\.[A-Za-z0-9_-]{16,}")


def redact(text: str) -> str:
    """Return ``text`` with credentials replaced. Cheap when there is nothing to hide."""
    if not text:
        return text
    lowered = text.lower()
    if "=" in text and any(key in lowered for key in _SENSITIVE_KEYS):
        text = _PARAM.sub(lambda m: f"{m.group(1)}={REDACTED}", text)
    if "bearer" in lowered:
        text = _BEARER.sub(lambda m: f"{m.group(1)}{REDACTED}", text)
    if "eyJ" in text:
        text = _JWT.sub("[REDACTED_JWT]", text)
    if "pbb_" in text:
        text = _BOT_TOKEN.sub("[REDACTED_BOT_TOKEN]", text)
    return text
