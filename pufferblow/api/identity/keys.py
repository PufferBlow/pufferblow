"""Identity keys: the P-256 signing keys a person's devices use to sign what they say in a call.

The instance only keeps public keys and hands them to whoever asks. It cannot sign for anyone, but it
*can* hand out a key that is not the person's (that is what a hostile instance would do), so the client
pins the first key it sees for each person and asks them to compare safety numbers; the key id here is
what both sides compute the same way.
"""

from __future__ import annotations

import base64
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric import ec

#: A person can have this many devices' keys at once.
MAX_KEYS_PER_USER = 10

_COORDINATE_BYTES = 32  # P-256


class InvalidIdentityKey(ValueError):
    """The key is not a usable P-256 public key. The message says what is wrong with it."""


def _b64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise InvalidIdentityKey("The key coordinates must be base64url text.")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:  # noqa: BLE001 - any decoding failure is the same problem
        raise InvalidIdentityKey("The key coordinates must be base64url text.") from exc


def validate_public_key(jwk: object) -> tuple[dict, str]:
    """Check a public key and return ``(canonical_jwk, key_id)``.

    The canonical form keeps only ``kty``, ``crv``, ``x`` and ``y`` (so two copies of one key always
    compare equal); the point must be on the curve.
    """
    if not isinstance(jwk, dict):
        raise InvalidIdentityKey("The public key must be a JWK object.")
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise InvalidIdentityKey("Only P-256 (EC) keys are supported.")
    if "d" in jwk:
        raise InvalidIdentityKey("That is a private key. Send only the public key.")
    x, y = _b64url_decode(jwk.get("x")), _b64url_decode(jwk.get("y"))
    if len(x) != _COORDINATE_BYTES or len(y) != _COORDINATE_BYTES:
        raise InvalidIdentityKey("The key coordinates are the wrong size for P-256.")
    try:
        ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()).public_key()
    except ValueError as exc:
        raise InvalidIdentityKey("That point is not on the P-256 curve.") from exc
    canonical = {"kty": "EC", "crv": "P-256", "x": base64.urlsafe_b64encode(x).rstrip(b"=").decode(), "y": base64.urlsafe_b64encode(y).rstrip(b"=").decode()}
    return canonical, key_id_of(x, y)


def key_id_of(x: bytes, y: bytes) -> str:
    """The first 32 hex characters of SHA-256 over ``x || y``. Clients compute the same."""
    return hashlib.sha256(x + y).hexdigest()[:32]


def to_json(canonical: dict) -> str:
    return json.dumps(canonical, separators=(",", ":"), sort_keys=True)
