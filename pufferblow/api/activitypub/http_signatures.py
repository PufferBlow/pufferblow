"""HTTP Signatures for ActivityPub delivery (draft-cavage-http-signatures).

This is the signature scheme Mastodon, Misskey, and Pleroma all use for
federated delivery — without it, a real-world peer either rejects an inbound
activity outright or heavily distrusts it. Pufferblow already generates and
stores a real RSA keypair per local actor (`ActivityPubManager._generate_keypair`,
`database/tables/activitypub.py`'s `public_key_pem`/`private_key_pem`); this
module is the missing piece that actually uses it to sign outbound requests
and verify inbound ones.

Signing string covers four pseudo/real headers, the set every mainstream AP
implementation expects: ``(request-target)``, ``host``, ``date``, ``digest``.
Algorithm is ``rsa-sha256`` (RSASSA-PKCS1-v1_5 + SHA-256) via the `cryptography`
library already used for keygen — no new dependency.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Mapping
from email.utils import format_datetime, parsedate_to_datetime
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

#: How stale a `Date` header may be before a signature is rejected outright.
#: Generous on purpose — federated delivery can legitimately queue/retry for
#: a while, and the inbox's own replay-dedup (by activity id) is the primary
#: defense against a genuine replay; this is a secondary sanity bound.
MAX_CLOCK_SKEW = timedelta(hours=12)

SIGNED_HEADERS = ("(request-target)", "host", "date", "digest")


def digest_header(body: bytes) -> str:
    """``Digest`` header value for a request body."""
    return "SHA-256=" + base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")


def key_id_for_actor(actor_uri: str) -> str:
    """The `keyId` this actor's signatures are made under.

    Matches the `publicKey.id` field `build_actor_document` already emits
    (`activitypub_manager.py`) — `f"{actor_uri}#main-key"`.
    """
    return f"{actor_uri}#main-key"


def _signing_string(method: str, path: str, host: str, date: str, digest: str) -> str:
    return (
        f"(request-target): {method.lower()} {path}\n"
        f"host: {host}\n"
        f"date: {date}\n"
        f"digest: {digest}"
    )


def sign_request(
    *, method: str, url: str, body: bytes, private_key_pem: str, key_id: str
) -> dict[str, str]:
    """Build the headers an outbound ActivityPub POST must carry.

    Returns `Digest`, `Date`, `Host`, and `Signature` — merge these into the
    request's existing headers before sending. `Host` is included explicitly
    (rather than left to the HTTP client) so the exact value used in the
    signing string is guaranteed to match what's sent on the wire.
    """
    parsed = urlsplit(url)
    host = parsed.netloc
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    date = format_datetime(datetime.now(timezone.utc), usegmt=True)
    digest = digest_header(body)
    signing_string = _signing_string(method, path, host, date, digest)

    private_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    signature_bytes = private_key.sign(
        signing_string.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256()
    )
    signature_b64 = base64.b64encode(signature_bytes).decode("ascii")

    signature_header = (
        f'keyId="{key_id}",algorithm="rsa-sha256",'
        f'headers="{" ".join(SIGNED_HEADERS)}",signature="{signature_b64}"'
    )
    return {"Digest": digest, "Date": date, "Host": host, "Signature": signature_header}


def _parse_signature_header(value: str) -> dict[str, str]:
    """Parse `Signature: keyId="...",algorithm="...",headers="...",signature="..."`."""
    params: dict[str, str] = {}
    for part in value.split(","):
        if "=" not in part:
            continue
        name, _, raw = part.strip().partition("=")
        params[name.strip()] = raw.strip().strip('"')
    return params


class SignatureVerificationError(Exception):
    """Raised by `verify_request` with a reason never shown to the caller's caller."""


def verify_request(
    *, method: str, path: str, headers: Mapping[str, str], body: bytes, public_key_pem: str
) -> None:
    """Verify an inbound request's `Signature` header.

    Raises `SignatureVerificationError` on any failure (missing header,
    stale date, digest mismatch, bad signature) — callers should catch this
    and respond with a generic 401, never echoing the specific reason back
    to the sender (same "don't disclose which part was wrong" posture used
    elsewhere in this codebase, e.g. masking "channel doesn't exist" vs "no
    access").

    `headers` must be case-insensitively keyed (FastAPI's `Request.headers`
    already is). `path` is the request path including any query string, as
    the sender would have signed it.
    """
    lowered = {k.lower(): v for k, v in headers.items()}

    signature_header = lowered.get("signature")
    if not signature_header:
        raise SignatureVerificationError("missing Signature header")
    params = _parse_signature_header(signature_header)
    for required in ("keyId", "algorithm", "headers", "signature"):
        if required not in params:
            raise SignatureVerificationError(f"Signature header missing '{required}'")
    if params["algorithm"] not in ("rsa-sha256", "hs2019"):
        raise SignatureVerificationError(f"unsupported algorithm {params['algorithm']!r}")

    date_value = lowered.get("date")
    if not date_value:
        raise SignatureVerificationError("missing Date header")
    try:
        parsed_date = parsedate_to_datetime(date_value)
        if parsed_date.tzinfo is None:
            parsed_date = parsed_date.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError) as exc:
        raise SignatureVerificationError(f"unparseable Date header: {exc}") from exc
    now = datetime.now(timezone.utc)
    if abs(now - parsed_date) > MAX_CLOCK_SKEW:
        raise SignatureVerificationError("Date header outside allowed clock skew")

    digest_value = lowered.get("digest")
    if not digest_value:
        raise SignatureVerificationError("missing Digest header")
    if digest_value != digest_header(body):
        raise SignatureVerificationError("Digest does not match body")

    host_value = lowered.get("host")
    if not host_value:
        raise SignatureVerificationError("missing Host header")

    signed_header_names = params["headers"].split()
    line_values = {
        "(request-target)": f"{method.lower()} {path}",
        "host": host_value,
        "date": date_value,
        "digest": digest_value,
    }
    try:
        lines = [f"{name}: {line_values[name]}" for name in signed_header_names]
    except KeyError as exc:
        raise SignatureVerificationError(f"signed an unknown pseudo-header {exc}") from exc
    signing_string = "\n".join(lines)

    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        public_key.verify(
            base64.b64decode(params["signature"]),
            signing_string.encode("utf-8"),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except (InvalidSignature, ValueError) as exc:
        raise SignatureVerificationError("signature does not verify") from exc
