"""Salted, slow password digests for the databases that have no encryption keys (SQLite).

On Postgres a password is stored encrypted with a per-user key. SQLite (the test database, and anything
that runs without keys) has none, so it stores a digest instead. A bare SHA-256 would be cheap to guess
and identical for identical passwords, so this uses scrypt with a random salt per password.
The cost is deliberately modest (about 20 ms): it is still salted and memory-hard, and the test suite
signs up many users.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

_N, _R, _P = 2**13, 8, 1
_PREFIX = "scrypt$"


def _derive(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=_N, r=_R, p=_P, dklen=32, maxmem=64 * 1024 * 1024)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    return _PREFIX + base64.b64encode(salt).decode("ascii") + "$" + base64.b64encode(_derive(password, salt)).decode("ascii")


def verify_password(stored: str | None, given: str) -> bool:
    """Constant-time check. Anything that is not a digest made by :func:`hash_password` never matches."""
    if not stored or not stored.startswith(_PREFIX):
        return False
    try:
        salt_b64, digest_b64 = stored[len(_PREFIX):].split("$", 1)
        salt, expected = base64.b64decode(salt_b64), base64.b64decode(digest_b64)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(_derive(given, salt), expected)
