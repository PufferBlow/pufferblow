"""A short-lived, signed statement from someone's home server: "this is alice@home, and she wants to join that server".

Joining another server does not make a new account there, so the server being joined needs a way to be sure the
person is who they say. Their home server says so, signed with the key of their ActivityPub actor: the same key the
rest of federation already trusts, and which anyone can fetch from the actor document. The assertion names the server it
is for, expires within a minute and carries a one-time nonce, so a copy captured on the way cannot be used for another
server, later, or twice.

Format: ``base64url(payload JSON) "." base64url(RSA-SHA256 signature of the first part)``.
"""

from __future__ import annotations

import base64
import json
import secrets
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

ASSERTION_TTL_SECONDS = 60
#: How far apart two servers' clocks may be before an assertion is refused.
CLOCK_SKEW_SECONDS = 30
VERSION = 1


class AssertionInvalid(ValueError):
    """The assertion cannot be accepted. The message is for logs; callers show nothing specific."""


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sign_assertion(*, private_key_pem: str, handle: str, actor_uri: str, issuer: str, audience: str, now: float | None = None) -> str:
    """The assertion for ``handle`` (``name@home``), good for ``audience`` (``host:port`` of the server being joined)."""
    issued = int(now if now is not None else time.time())
    payload = {
        "v": VERSION,
        "iss": issuer,
        "sub": handle,
        "actor": actor_uri,
        "aud": audience,
        "nonce": secrets.token_hex(16),
        "iat": issued,
        "exp": issued + ASSERTION_TTL_SECONDS,
    }
    body = _b64(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    signature = key.sign(body.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return f"{body}.{_b64(signature)}"


def read_claims(token: str) -> dict[str, Any]:
    """The claims in an assertion, **not yet trusted**: enough to find whose key to check it with."""
    try:
        body, _signature = token.split(".", 1)
        claims = json.loads(_unb64(body))
    except Exception as exc:
        raise AssertionInvalid("malformed") from exc
    if not isinstance(claims, dict) or claims.get("v") != VERSION:
        raise AssertionInvalid("unsupported version")
    for field in ("iss", "sub", "actor", "aud", "nonce"):
        if not isinstance(claims.get(field), str) or not claims[field]:
            raise AssertionInvalid(f"missing {field}")
    if not isinstance(claims.get("iat"), int) or not isinstance(claims.get("exp"), int):
        raise AssertionInvalid("missing times")
    return claims


def verify_assertion(token: str, *, public_key_pem: str, audience: str, now: float | None = None) -> dict[str, Any]:
    """The claims, once the signature, audience and time window all check out; otherwise ``AssertionInvalid``."""
    claims = read_claims(token)
    current = now if now is not None else time.time()
    if claims["aud"] != audience:
        raise AssertionInvalid("for another server")
    if claims["exp"] < current - CLOCK_SKEW_SECONDS or claims["iat"] > current + CLOCK_SKEW_SECONDS:
        raise AssertionInvalid("expired")
    if claims["exp"] - claims["iat"] > ASSERTION_TTL_SECONDS + CLOCK_SKEW_SECONDS:
        raise AssertionInvalid("lives too long")
    body, signature = token.split(".", 1)
    try:
        key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        key.verify(_unb64(signature), body.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise AssertionInvalid("bad signature") from exc
    return claims
