"""Stable error codes for the PufferBlow API.

Every error response carries an ``error_code`` from this registry.
Third-party clients (alternate apps, mobile, CLI, bots) pin against
these strings — they are part of the wire contract, NOT internal
identifiers. Renaming a code is a breaking change.

Adding a code: pick a dotted namespace (e.g. ``stickers.alias_taken``),
add an ``ErrorSpec`` to ``ERROR_REGISTRY``, and document it in
``docs/ERROR_CODES.md``. The first segment matches the feature area
(``auth``, ``stickers``, ``friends``, ``rate_limit``, …); the
second segment is the specific condition.

Default user messages are written so they can be shown to the user
verbatim — no placeholder substitution needed. Call sites that want
to inject context (filename, alias, count) override
``user_message`` on the ``ApiError`` raise; the registry default is
the floor, not the ceiling.

Status codes follow REST conventions:

  * 400 — client-side validation, malformed request
  * 401 — auth required (missing / invalid token)
  * 403 — authenticated but forbidden (privilege, ban, scope)
  * 404 — resource doesn't exist or isn't visible to caller
  * 409 — conflict (duplicate, concurrent edit, alias collision)
  * 413 — payload too large
  * 422 — request shape valid but business validation failed
  * 429 — rate limited
  * 500 — server-side bug; emit ``request_id`` for support
  * 503 — temporarily unavailable (dependency down, maintenance)
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ErrorSpec:
    """A single entry in the error-code registry."""

    code: str
    """Stable identifier surfaced on the wire. Never rename."""

    status: int
    """HTTP status the envelope ships with."""

    user_message: str
    """Default human-facing message. Safe to show verbatim."""

    retryable: bool = False
    """Hint to clients: is this a transient condition worth a retry?
    Auth / rate-limit / dependency-down → True. Validation /
    permission / conflict → False."""

    description: str = ""
    """Internal explainer — emitted into the generated docs page."""


class ErrorCode:
    """String constants for every error code the API emits.

    Use as ``ApiError(ErrorCode.AUTH_INVALID_TOKEN)``; constants
    keep IDEs in the loop and make refactors searchable.
    """

    # ── Auth (401 / 403) ────────────────────────────────────────
    AUTH_TOKEN_REQUIRED = "auth.token_required"
    AUTH_INVALID_TOKEN = "auth.invalid_token"
    AUTH_USER_BANNED = "auth.user_banned"
    AUTH_PRIVILEGE_DENIED = "auth.privilege_denied"
    # Sign-in: deliberately collapsed code covering both
    # "username doesn't exist" and "wrong password". One code on the
    # wire prevents username enumeration; the server-side ``message``
    # field carries the truth (for logs) while ``user_message`` stays
    # generic. Do NOT split this into two codes — that would re-leak
    # the distinction we're trying to hide.
    AUTH_INVALID_CREDENTIALS = "auth.invalid_credentials"
    # Sign-in: the user exists on this instance's records but is
    # actually homed on a different one (federation cleanup case).
    AUTH_INSTANCE_MISMATCH = "auth.instance_mismatch"
    # Sign-in: too many failed attempts; backoff window active.
    # Distinct from the generic rate_limit because the action is
    # specifically "you tried wrong credentials too many times" and
    # the user-facing copy should reflect that.
    AUTH_ACCOUNT_LOCKED = "auth.account_locked"
    # Sign-up errors. ``username_taken`` is a 409 conflict;
    # ``username_invalid`` covers format / reserved-word violations;
    # ``password_too_weak`` covers length / complexity rules.
    AUTH_USERNAME_TAKEN = "auth.username_taken"
    AUTH_USERNAME_INVALID = "auth.username_invalid"
    AUTH_PASSWORD_TOO_WEAK = "auth.password_too_weak"
    # Instance hasn't completed the setup CLI yet — sign-ups
    # disabled until the operator finishes initialising the
    # instance's encryption keys / server row.
    AUTH_SIGNUP_DISABLED = "auth.signup_disabled"
    # Refresh-token specific (separate from invalid_token because
    # the client's recovery action differs — refresh failure means
    # "log in again" rather than "your access token rolled, retry").
    AUTH_REFRESH_TOKEN_EXPIRED = "auth.refresh_token_expired"
    AUTH_REFRESH_TOKEN_INVALID = "auth.refresh_token_invalid"
    # Reset-auth-token specific — the 2-second cooldown after a
    # successful reset, plus the wrong-password case scoped to this
    # endpoint (separate from invalid_credentials so the user
    # doesn't get an enumeration-resistant generic message on a
    # form where they JUST entered their old password).
    AUTH_RESET_COOLDOWN = "auth.reset_cooldown"
    AUTH_RESET_PASSWORD_WRONG = "auth.reset_password_wrong"

    # ── Validation (400 / 422) ──────────────────────────────────
    VALIDATION_FIELD_REQUIRED = "validation.field_required"
    VALIDATION_FIELD_TYPE = "validation.field_type"
    VALIDATION_FIELD_RANGE = "validation.field_range"
    VALIDATION_PAYLOAD_MALFORMED = "validation.payload_malformed"
    VALIDATION_PAYLOAD_TOO_LARGE = "validation.payload_too_large"

    # ── Resource lifecycle (404 / 409) ──────────────────────────
    RESOURCE_NOT_FOUND = "resource.not_found"
    RESOURCE_CONFLICT = "resource.conflict"
    RESOURCE_ALREADY_EXISTS = "resource.already_exists"

    # ── Rate limiting (429) ─────────────────────────────────────
    RATE_LIMIT_EXCEEDED = "rate_limit.exceeded"
    RATE_LIMIT_IP_BLOCKED = "rate_limit.ip_blocked"

    # ── Channels ────────────────────────────────────────────────
    CHANNELS_NOT_FOUND = "channels.not_found"
    CHANNELS_ACCESS_DENIED = "channels.access_denied"
    CHANNELS_VOICE_ONLY_NO_TEXT = "channels.voice_only_no_text"

    # ── Messages ────────────────────────────────────────────────
    MESSAGES_NOT_FOUND = "messages.not_found"
    MESSAGES_TOO_LONG = "messages.too_long"
    MESSAGES_EMPTY = "messages.empty"
    MESSAGES_ATTACHMENT_TOO_LARGE = "messages.attachment_too_large"
    MESSAGES_TIMED_OUT = "messages.timed_out"

    # ── Stickers ────────────────────────────────────────────────
    STICKERS_NOT_FOUND = "stickers.not_found"
    STICKERS_NOT_AVAILABLE = "stickers.not_available"
    STICKERS_ALIAS_TAKEN = "stickers.alias_taken"
    STICKERS_INVALID_ALIAS = "stickers.invalid_alias"
    STICKERS_INVALID_DISPLAY_NAME = "stickers.invalid_display_name"
    STICKERS_UNSUPPORTED_TYPE = "stickers.unsupported_type"
    STICKERS_TOO_LARGE = "stickers.too_large"

    # ── Friends ─────────────────────────────────────────────────
    FRIENDS_SELF_RELATION = "friends.self_relation"
    FRIENDS_DUPLICATE_REQUEST = "friends.duplicate_request"
    FRIENDS_NOT_FOUND = "friends.not_found"
    FRIENDS_NOT_RECIPIENT = "friends.not_recipient"
    FRIENDS_BLOCKED = "friends.blocked"

    # ── Storage / uploads ───────────────────────────────────────
    STORAGE_QUOTA_EXCEEDED = "storage.quota_exceeded"
    STORAGE_UNSUPPORTED_TYPE = "storage.unsupported_type"
    STORAGE_UPLOAD_FAILED = "storage.upload_failed"

    # ── Federation ──────────────────────────────────────────────
    FEDERATION_WEBFINGER_FAILED = "federation.webfinger_failed"
    FEDERATION_REMOTE_UNREACHABLE = "federation.remote_unreachable"
    FEDERATION_INVALID_HANDLE = "federation.invalid_handle"

    # ── Server / catch-all ──────────────────────────────────────
    SERVER_INTERNAL_ERROR = "server.internal_error"
    SERVER_UNAVAILABLE = "server.unavailable"
    SERVER_FEATURE_DISABLED = "server.feature_disabled"

    # ── Client-emitted codes ────────────────────────────────────
    # These codes are NEVER emitted by the server — they're
    # produced client-side when a request fails before / instead of
    # reaching the instance. Listed here in the canonical registry
    # because the contract is the same: third-party clients should
    # use these exact strings so cross-client telemetry, logs, and
    # support tooling stay consistent. The server's own handler
    # path can never produce them, but the registry is the
    # authoritative namespace.
    #
    # Naming convention: ``client.*`` for "your machine couldn't
    # talk to the instance" cases, ``instance.*`` for "the device
    # is fine but THIS particular instance isn't responding" cases.
    # The distinction matters because federation has multiple
    # instances in play — one being down shouldn't read as "you're
    # offline."
    CLIENT_NETWORK_OFFLINE = "client.network_offline"
    CLIENT_NETWORK_TIMEOUT = "client.network_timeout"
    CLIENT_CORS_BLOCKED = "client.cors_blocked"
    INSTANCE_UNREACHABLE = "instance.unreachable"
    INSTANCE_HOME_UNREACHABLE = "instance.home_unreachable"


# Registry: code → ErrorSpec. Source of truth for status, default
# user message, and retry hint. ``register_error_handlers`` and the
# docs generator both read from here, so adding an entry is the only
# action needed to ship a new code.
ERROR_REGISTRY: dict[str, ErrorSpec] = {
    # ── Auth ────────────────────────────────────────────────────
    ErrorCode.AUTH_TOKEN_REQUIRED: ErrorSpec(
        ErrorCode.AUTH_TOKEN_REQUIRED, 401,
        "You need to sign in to do that.",
        description="Request reached an authenticated route without an auth_token "
                    "query / form param.",
    ),
    ErrorCode.AUTH_INVALID_TOKEN: ErrorSpec(
        ErrorCode.AUTH_INVALID_TOKEN, 401,
        "Your session has expired. Sign in again.",
        description="auth_token failed verification — expired, revoked, or "
                    "issued to a user that no longer exists.",
    ),
    ErrorCode.AUTH_USER_BANNED: ErrorSpec(
        ErrorCode.AUTH_USER_BANNED, 403,
        "This account has been banned from this instance.",
        description="User row has the banned flag set. Permanent until lifted.",
    ),
    ErrorCode.AUTH_PRIVILEGE_DENIED: ErrorSpec(
        ErrorCode.AUTH_PRIVILEGE_DENIED, 403,
        "You don't have permission to do that.",
        description="User authenticated but lacks the privilege the route requires "
                    "(see ``details.privilege`` for which one).",
    ),
    ErrorCode.AUTH_INVALID_CREDENTIALS: ErrorSpec(
        ErrorCode.AUTH_INVALID_CREDENTIALS, 401,
        "Invalid username or password.",
        description="Sign-in failed. Deliberately ambiguous — covers both "
                    "'username not found' and 'wrong password' to prevent "
                    "username enumeration. Server-side ``message`` carries "
                    "the specific reason for logs; the wire/user message stays "
                    "generic.",
    ),
    ErrorCode.AUTH_INSTANCE_MISMATCH: ErrorSpec(
        ErrorCode.AUTH_INSTANCE_MISMATCH, 403,
        "That account doesn't belong to this instance.",
        description="Credentials matched a user_id known to this instance "
                    "(via federation), but the user is homed elsewhere. Sign "
                    "in on the home instance instead.",
    ),
    ErrorCode.AUTH_ACCOUNT_LOCKED: ErrorSpec(
        ErrorCode.AUTH_ACCOUNT_LOCKED, 429,
        "Too many failed sign-in attempts. Try again in a few minutes.",
        retryable=True,
        description="The per-account sign-in lockout window is active. "
                    "``retry_after_seconds`` carries the wait.",
    ),
    ErrorCode.AUTH_USERNAME_TAKEN: ErrorSpec(
        ErrorCode.AUTH_USERNAME_TAKEN, 409,
        "That username is taken. Pick another.",
        description="Sign-up: ``users.username`` unique-index collision. "
                    "Surface on the username field, not as a banner.",
    ),
    ErrorCode.AUTH_USERNAME_INVALID: ErrorSpec(
        ErrorCode.AUTH_USERNAME_INVALID, 400,
        "Username must be 3–32 characters and use only letters, digits, "
        "dots, dashes, or underscores.",
        description="Sign-up / rename: format violation. ``details.field`` "
                    "is ``'username'`` so the client highlights the input.",
    ),
    ErrorCode.AUTH_PASSWORD_TOO_WEAK: ErrorSpec(
        ErrorCode.AUTH_PASSWORD_TOO_WEAK, 400,
        "Password must be at least 8 characters.",
        description="Sign-up / change-password: failed strength check. "
                    "``details.field`` is ``'password'`` and ``details.rules`` "
                    "carries the list of unsatisfied checks (``min_length``, "
                    "``max_length``, …).",
    ),
    ErrorCode.AUTH_SIGNUP_DISABLED: ErrorSpec(
        ErrorCode.AUTH_SIGNUP_DISABLED, 503,
        "Sign-ups are disabled on this instance.",
        description="Instance hasn't completed its setup CLI, or the operator "
                    "turned new registrations off. Operator action required.",
    ),
    ErrorCode.AUTH_REFRESH_TOKEN_EXPIRED: ErrorSpec(
        ErrorCode.AUTH_REFRESH_TOKEN_EXPIRED, 401,
        "Your session expired. Sign in again.",
        description="Refresh token past its expiry. Client should drop both "
                    "tokens and bounce to the login page.",
    ),
    ErrorCode.AUTH_REFRESH_TOKEN_INVALID: ErrorSpec(
        ErrorCode.AUTH_REFRESH_TOKEN_INVALID, 401,
        "Your session is no longer valid. Sign in again.",
        description="Refresh token signature failed verification, or the "
                    "token was revoked. Client behaviour identical to expired.",
    ),
    ErrorCode.AUTH_RESET_COOLDOWN: ErrorSpec(
        ErrorCode.AUTH_RESET_COOLDOWN, 429,
        "Wait a moment before resetting your auth token again.",
        retryable=True,
        description="Per-user reset cooldown active. ``retry_after_seconds`` "
                    "carries the wait.",
    ),
    ErrorCode.AUTH_RESET_PASSWORD_WRONG: ErrorSpec(
        ErrorCode.AUTH_RESET_PASSWORD_WRONG, 403,
        "That password doesn't match.",
        description="Wrong password supplied to the reset-auth-token endpoint. "
                    "Distinct from sign-in's invalid_credentials — on this "
                    "form the user just typed their current password and "
                    "deserves a specific 'that's wrong' message, not the "
                    "enumeration-safe generic one.",
    ),

    # ── Validation ──────────────────────────────────────────────
    ErrorCode.VALIDATION_FIELD_REQUIRED: ErrorSpec(
        ErrorCode.VALIDATION_FIELD_REQUIRED, 400,
        "A required field is missing.",
        description="Field listed in ``details.field`` was absent or empty.",
    ),
    ErrorCode.VALIDATION_FIELD_TYPE: ErrorSpec(
        ErrorCode.VALIDATION_FIELD_TYPE, 400,
        "A field has the wrong type.",
        description="Field present but wrong shape — e.g. expected int, got string.",
    ),
    ErrorCode.VALIDATION_FIELD_RANGE: ErrorSpec(
        ErrorCode.VALIDATION_FIELD_RANGE, 400,
        "A field is out of the allowed range.",
        description="``details.field`` value violates min/max/length constraint.",
    ),
    ErrorCode.VALIDATION_PAYLOAD_MALFORMED: ErrorSpec(
        ErrorCode.VALIDATION_PAYLOAD_MALFORMED, 400,
        "The request couldn't be understood.",
        description="JSON parse failure / multipart parse failure / general "
                    "shape error before Pydantic validation could even run.",
    ),
    ErrorCode.VALIDATION_PAYLOAD_TOO_LARGE: ErrorSpec(
        ErrorCode.VALIDATION_PAYLOAD_TOO_LARGE, 413,
        "That request is too large.",
        description="Body / attachment exceeds instance configured limit.",
    ),

    # ── Resource lifecycle ──────────────────────────────────────
    ErrorCode.RESOURCE_NOT_FOUND: ErrorSpec(
        ErrorCode.RESOURCE_NOT_FOUND, 404,
        "That doesn't exist anymore.",
        description="Generic 'I looked it up and it isn't there.' Prefer a "
                    "feature-specific code (e.g. ``channels.not_found``) when "
                    "the area is known.",
    ),
    ErrorCode.RESOURCE_CONFLICT: ErrorSpec(
        ErrorCode.RESOURCE_CONFLICT, 409,
        "Someone changed that before you did — refresh and try again.",
        description="Optimistic-concurrency-style conflict. ``details`` may "
                    "carry the conflicting state.",
    ),
    ErrorCode.RESOURCE_ALREADY_EXISTS: ErrorSpec(
        ErrorCode.RESOURCE_ALREADY_EXISTS, 409,
        "That already exists.",
        description="Generic uniqueness collision.",
    ),

    # ── Rate limiting ───────────────────────────────────────────
    ErrorCode.RATE_LIMIT_EXCEEDED: ErrorSpec(
        ErrorCode.RATE_LIMIT_EXCEEDED, 429,
        "You're going too fast. Try again in a moment.",
        retryable=True,
        description="Per-IP rate-limit bucket exhausted. ``retry_after_seconds`` "
                    "is populated.",
    ),
    ErrorCode.RATE_LIMIT_IP_BLOCKED: ErrorSpec(
        ErrorCode.RATE_LIMIT_IP_BLOCKED, 403,
        "Your IP has been blocked by this instance.",
        description="IP added to the blocked-IPs table (manual or automated "
                    "by abuse heuristics). Permanent until lifted by an "
                    "instance admin.",
    ),

    # ── Channels ────────────────────────────────────────────────
    ErrorCode.CHANNELS_NOT_FOUND: ErrorSpec(
        ErrorCode.CHANNELS_NOT_FOUND, 404,
        "That channel doesn't exist or you don't have access to it.",
        description="Channel id doesn't match a row OR the channel is private "
                    "and the viewer isn't a member. The two cases share a code "
                    "so the API doesn't leak channel existence.",
    ),
    ErrorCode.CHANNELS_ACCESS_DENIED: ErrorSpec(
        ErrorCode.CHANNELS_ACCESS_DENIED, 403,
        "You can't do that in this channel.",
        description="User has channel membership but lacks the per-channel "
                    "privilege the action requires.",
    ),
    ErrorCode.CHANNELS_VOICE_ONLY_NO_TEXT: ErrorSpec(
        ErrorCode.CHANNELS_VOICE_ONLY_NO_TEXT, 400,
        "Messages can't be sent to a voice-only channel.",
        description="The channel's type is 'voice'; switch to a text or mixed "
                    "channel for text messages.",
    ),

    # ── Messages ────────────────────────────────────────────────
    ErrorCode.MESSAGES_NOT_FOUND: ErrorSpec(
        ErrorCode.MESSAGES_NOT_FOUND, 404,
        "That message is gone.",
        description="Message ID doesn't exist in the channel — deleted, never "
                    "existed, or in a channel the viewer can't see.",
    ),
    ErrorCode.MESSAGES_TOO_LONG: ErrorSpec(
        ErrorCode.MESSAGES_TOO_LONG, 400,
        "That message is too long for this instance.",
        description="Body exceeds the instance's max_message_length setting. "
                    "``details.limit`` carries the configured ceiling.",
    ),
    ErrorCode.MESSAGES_EMPTY: ErrorSpec(
        ErrorCode.MESSAGES_EMPTY, 400,
        "Add a message or an attachment before sending.",
        description="Empty body + no attachments + no stickers.",
    ),
    ErrorCode.MESSAGES_ATTACHMENT_TOO_LARGE: ErrorSpec(
        ErrorCode.MESSAGES_ATTACHMENT_TOO_LARGE, 413,
        "Those attachments are too big for this instance.",
        description="Combined attachment size exceeds instance "
                    "max_total_attachment_mb setting.",
    ),
    ErrorCode.MESSAGES_TIMED_OUT: ErrorSpec(
        ErrorCode.MESSAGES_TIMED_OUT, 403,
        "You're in a timeout and can't send messages right now.",
        description="Moderator-issued timeout active on the user. "
                    "``details.until`` carries the expiry timestamp.",
    ),

    # ── Stickers ────────────────────────────────────────────────
    ErrorCode.STICKERS_NOT_FOUND: ErrorSpec(
        ErrorCode.STICKERS_NOT_FOUND, 404,
        "That sticker doesn't exist.",
        description="sticker_id has no matching row.",
    ),
    ErrorCode.STICKERS_NOT_AVAILABLE: ErrorSpec(
        ErrorCode.STICKERS_NOT_AVAILABLE, 404,
        "That sticker isn't available for use right now.",
        description="Sticker is deactivated (``is_active=False``).",
    ),
    ErrorCode.STICKERS_ALIAS_TAKEN: ErrorSpec(
        ErrorCode.STICKERS_ALIAS_TAKEN, 409,
        "That sticker shortcode is already in use.",
        description="``details.alias`` is already assigned to a different sticker.",
    ),
    ErrorCode.STICKERS_INVALID_ALIAS: ErrorSpec(
        ErrorCode.STICKERS_INVALID_ALIAS, 400,
        "Sticker shortcode must be 2–32 lowercase letters, digits, or underscores.",
        description="Alias failed the ``^[a-z0-9_]{2,32}$`` pattern.",
    ),
    ErrorCode.STICKERS_INVALID_DISPLAY_NAME: ErrorSpec(
        ErrorCode.STICKERS_INVALID_DISPLAY_NAME, 400,
        "Sticker name must be 1–64 printable characters.",
        description="display_name was empty / too long / contained control chars.",
    ),
    ErrorCode.STICKERS_UNSUPPORTED_TYPE: ErrorSpec(
        ErrorCode.STICKERS_UNSUPPORTED_TYPE, 400,
        "Stickers must be PNG, WebP, GIF, or JPEG.",
        description="File MIME type isn't in the allow-list.",
    ),
    ErrorCode.STICKERS_TOO_LARGE: ErrorSpec(
        ErrorCode.STICKERS_TOO_LARGE, 413,
        "Stickers must be 512 KB or smaller.",
        description="File exceeded ``MAX_STICKER_BYTES``.",
    ),

    # ── Friends ─────────────────────────────────────────────────
    ErrorCode.FRIENDS_SELF_RELATION: ErrorSpec(
        ErrorCode.FRIENDS_SELF_RELATION, 400,
        "You can't friend yourself.",
        description="Caller attempted to send / accept / block themselves.",
    ),
    ErrorCode.FRIENDS_DUPLICATE_REQUEST: ErrorSpec(
        ErrorCode.FRIENDS_DUPLICATE_REQUEST, 409,
        "There's already a friendship or pending request with that user.",
        description="Friendship row exists in some state between the two users.",
    ),
    ErrorCode.FRIENDS_NOT_FOUND: ErrorSpec(
        ErrorCode.FRIENDS_NOT_FOUND, 404,
        "Couldn't find that user to add as a friend.",
        description="Handle resolution returned no matching local user / shadow "
                    "user, OR the friendship_id passed doesn't exist.",
    ),
    ErrorCode.FRIENDS_NOT_RECIPIENT: ErrorSpec(
        ErrorCode.FRIENDS_NOT_RECIPIENT, 403,
        "Only the person who received the request can accept it.",
        description="Accept attempt by someone other than the addressee.",
    ),
    ErrorCode.FRIENDS_BLOCKED: ErrorSpec(
        ErrorCode.FRIENDS_BLOCKED, 403,
        "That user isn't accepting friend requests.",
        description="Recipient has the caller in their friend-request blocks. "
                    "Wire-level message is intentionally vague — we don't tell "
                    "the would-be sender 'you're blocked by them'.",
    ),

    # ── Storage ─────────────────────────────────────────────────
    ErrorCode.STORAGE_QUOTA_EXCEEDED: ErrorSpec(
        ErrorCode.STORAGE_QUOTA_EXCEEDED, 413,
        "This instance is out of storage space.",
        description="Instance-wide storage allocation exhausted. "
                    "Operator action required.",
    ),
    ErrorCode.STORAGE_UNSUPPORTED_TYPE: ErrorSpec(
        ErrorCode.STORAGE_UNSUPPORTED_TYPE, 400,
        "That file type isn't allowed.",
        description="MIME type not in the instance's upload allow-list.",
    ),
    ErrorCode.STORAGE_UPLOAD_FAILED: ErrorSpec(
        ErrorCode.STORAGE_UPLOAD_FAILED, 500,
        "Couldn't save that file. Try again in a moment.",
        retryable=True,
        description="Generic upload pipeline error. Storage backend down, "
                    "transient I/O failure, etc.",
    ),

    # ── Federation ──────────────────────────────────────────────
    ErrorCode.FEDERATION_WEBFINGER_FAILED: ErrorSpec(
        ErrorCode.FEDERATION_WEBFINGER_FAILED, 404,
        "Couldn't find that user on the remote instance.",
        description="WebFinger lookup returned no matching actor.",
    ),
    ErrorCode.FEDERATION_REMOTE_UNREACHABLE: ErrorSpec(
        ErrorCode.FEDERATION_REMOTE_UNREACHABLE, 503,
        "The remote instance isn't responding right now.",
        retryable=True,
        description="HTTP error reaching remote actor / inbox / outbox.",
    ),
    ErrorCode.FEDERATION_INVALID_HANDLE: ErrorSpec(
        ErrorCode.FEDERATION_INVALID_HANDLE, 400,
        "That looks like an invalid user handle.",
        description="Handle parsing failed (e.g. expected ``user@host``).",
    ),

    # ── Server / catch-all ──────────────────────────────────────
    ErrorCode.SERVER_INTERNAL_ERROR: ErrorSpec(
        ErrorCode.SERVER_INTERNAL_ERROR, 500,
        "Something went wrong on the server. The team's been notified.",
        retryable=True,
        description="Unhandled exception reached the catch-all handler. "
                    "``request_id`` is the support-ticket key.",
    ),
    ErrorCode.SERVER_UNAVAILABLE: ErrorSpec(
        ErrorCode.SERVER_UNAVAILABLE, 503,
        "The server is temporarily unavailable. Try again in a moment.",
        retryable=True,
        description="Dependency outage (DB, memcache, federation backbone) "
                    "OR maintenance mode.",
    ),
    ErrorCode.SERVER_FEATURE_DISABLED: ErrorSpec(
        ErrorCode.SERVER_FEATURE_DISABLED, 503,
        "This instance has that feature turned off.",
        description="Feature gated by instance config and explicitly disabled "
                    "by the operator.",
    ),

    # ── Client-emitted codes ────────────────────────────────────
    # Registry entries for codes the server never produces but
    # clients use. Status is 0 (no HTTP exchange happened) — that's
    # the sentinel for "no response received" across the contract.
    # ``retryable=True`` because reconnection / DNS recovery / a
    # restarted instance are all transient by nature.
    ErrorCode.CLIENT_NETWORK_OFFLINE: ErrorSpec(
        ErrorCode.CLIENT_NETWORK_OFFLINE, 0,
        "You're offline. Reconnect to keep chatting.",
        retryable=True,
        description="The CLIENT'S device has no internet — confirmed by "
                    "``navigator.onLine === false`` or the platform "
                    "equivalent. All instances will be unreachable "
                    "until the device comes back online. Distinct from "
                    "``instance.unreachable`` which only means THIS "
                    "instance is unreachable.",
    ),
    ErrorCode.CLIENT_NETWORK_TIMEOUT: ErrorSpec(
        ErrorCode.CLIENT_NETWORK_TIMEOUT, 0,
        "The server took too long to respond. Try again in a moment.",
        retryable=True,
        description="Request started but no response within the client's "
                    "timeout. Different from offline — the device DOES "
                    "have internet, the server just isn't replying fast "
                    "enough. Suggest retry; if it keeps happening, the "
                    "instance may be ``instance.unreachable``.",
    ),
    ErrorCode.CLIENT_CORS_BLOCKED: ErrorSpec(
        ErrorCode.CLIENT_CORS_BLOCKED, 0,
        "Your browser blocked this request. The server may be misconfigured.",
        description="Browser refused the cross-origin response. Almost "
                    "always an operator-side misconfiguration (missing "
                    "``Access-Control-Allow-Origin`` header). Not "
                    "retryable from the user's side.",
    ),
    ErrorCode.INSTANCE_UNREACHABLE: ErrorSpec(
        ErrorCode.INSTANCE_UNREACHABLE, 0,
        "Couldn't reach that instance. It may be offline.",
        retryable=True,
        description="The DEVICE is online (other domains work) but this "
                    "specific instance didn't respond — DNS miss, "
                    "connection refused, or the instance is down. "
                    "Federation-relevant: a remote instance being "
                    "unreachable is a normal, expected state in a "
                    "federated network and should NOT be surfaced as "
                    "'you're offline'.",
    ),
    ErrorCode.INSTANCE_HOME_UNREACHABLE: ErrorSpec(
        ErrorCode.INSTANCE_HOME_UNREACHABLE, 0,
        "Your home instance is offline. Some features won't work until it's back.",
        retryable=True,
        description="Same root cause as ``instance.unreachable`` but the "
                    "affected instance is the user's HOME instance — the "
                    "one that holds their identity, friend graph, and "
                    "private channels. Clients should surface this more "
                    "prominently than a remote instance being down: a "
                    "remote being down disables ONE conversation; the "
                    "home being down disables most operations.",
    ),
}


def get_error_spec(code: str) -> ErrorSpec:
    """Look up a spec by code. Falls back to ``SERVER_INTERNAL_ERROR``
    when the code isn't registered — better to ship an envelope with
    a recognisable shape than to crash the handler. The fallback path
    logs a warning at the call site.
    """
    return ERROR_REGISTRY.get(code, ERROR_REGISTRY[ErrorCode.SERVER_INTERNAL_ERROR])
