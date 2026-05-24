# PufferBlow API — Error Handling Contract

This document is the normative reference for every error PufferBlow's
HTTP API can return. **Third-party clients** (alternate apps, mobile,
CLI, bots, integrations) consume this contract directly — pin against
the `error_code` strings, not against status codes or human-facing
messages.

## Envelope

Every error response, regardless of which route raised, ships this
shape:

```json
{
  "status_code": 409,
  "error_code": "stickers.alias_taken",
  "message": "Alias ':party_parrot:' is already taken",
  "user_message": "The shortcode ':party_parrot:' is already in use.",
  "details": {
    "alias": "party_parrot"
  },
  "request_id": "1c8a3f0e-7d6e-4a3b-8a1e-92b8f1f0d9a2",
  "retry_after_seconds": null
}
```

### Fields

| Field | Type | Always present | Notes |
|---|---|---|---|
| `status_code` | int | yes | HTTP status; matches the response status line. |
| `error_code` | string | yes | The stable identifier. Pin clients against this. |
| `message` | string | yes | Developer / log-oriented description. May contain technical context. |
| `user_message` | string | yes | Safe to show users verbatim. Pre-formatted; no placeholder substitution needed. |
| `details` | object | yes (may be empty) | Structured context — `field`, `alias`, `limit`, `actual`, etc. See per-code docs below. |
| `request_id` | string \| null | yes | Correlation id; matches the `X-Request-ID` response header. Paste this when reporting bugs. |
| `retry_after_seconds` | int \| null | yes | Populated for `rate_limit.*` and some `server.*` codes. Honour with backoff. |

### Headers

| Header | Notes |
|---|---|
| `X-Request-ID` | Same value as the envelope's `request_id`. Useful when only headers are exposed (e.g. CDN logs). |
| `Retry-After` | Set only when `retry_after_seconds` is populated. Standard HTTP semantic; well-behaved clients should honour it. |

## Client semantics

- **Pin on `error_code`.** Status codes alone don't carry enough
  information (`404` can mean "user doesn't exist", "channel is private",
  "sticker was deleted" — all different actions).
- **Show `user_message` to users.** Don't render `message` —
  it may contain stack-trace-adjacent technical context.
- **Honour `retry_after_seconds`.** When present, the server has
  asked you to wait. Show a countdown / disable the action until
  it elapses.
- **Surface `request_id` in support flows.** When users hit a bug,
  including the id in their report lets operators correlate to logs
  immediately.

### Versioning

The envelope schema is additive: new optional fields may appear
without notice. Field **renames or removals** require a new code
namespace + a deprecation cycle. The current schema version is
implicit (v1); clients should ignore unknown fields.

## Error code reference

Codes follow a dotted convention: `<area>.<condition>`. The first
segment names the feature area (`auth`, `stickers`, `friends`,
`rate_limit`, …); the second segment is the specific condition.

The default `user_message` is what clients will see when the
server doesn't override it. Routes can override it on a per-raise
basis to inject specific context (filename, alias, count, …).

### Auth

| Code | HTTP | Default `user_message` | When |
|---|---|---|---|
| `auth.token_required` | 401 | You need to sign in to do that. | Auth required route reached without an `auth_token`. |
| `auth.invalid_token` | 401 | Your session has expired. Sign in again. | Token failed verification — expired, revoked, or user no longer exists. |
| `auth.user_banned` | 403 | This account has been banned from this instance. | User row has the banned flag set. |
| `auth.privilege_denied` | 403 | You don't have permission to do that. | Authenticated but missing the required privilege. `details.privilege` carries the name. |
| `auth.invalid_credentials` | 401 | Invalid username or password. | **Deliberately ambiguous** — covers both "username not found" and "wrong password" to prevent username enumeration. Client must not split this into two messages. |
| `auth.instance_mismatch` | 403 | That account doesn't belong to this instance. | Account is homed on a different instance (federation cleanup case). |
| `auth.account_locked` | 429 | Too many failed sign-in attempts. Try again in a few minutes. | Per-account sign-in lockout active. `retry_after_seconds` populated. |
| `auth.username_taken` | 409 | That username is taken. Pick another. | Sign-up / rename: unique-index collision. Surface on the username field. `details.field` is `'username'` or `'new_username'`. |
| `auth.username_invalid` | 400 | Username must be 3–32 characters and use only letters, digits, dots, dashes, or underscores. | Format violation. `details.field` is `'username'`. |
| `auth.password_too_weak` | 400 | Password must be at least 8 characters. | `details.rules` lists which checks failed (`min_length`, `max_length`). |
| `auth.signup_disabled` | 503 | Sign-ups are disabled on this instance. | Setup CLI not run, or operator turned registrations off. |
| `auth.refresh_token_expired` | 401 | Your session expired. Sign in again. | Refresh token past expiry. Client drops both tokens, bounces to login. |
| `auth.refresh_token_invalid` | 401 | Your session is no longer valid. Sign in again. | Refresh token signature failed or was revoked. Same client behaviour as expired. |
| `auth.reset_cooldown` | 429 | Wait a moment before resetting your auth token again. | Per-user reset cooldown. `retry_after_seconds` populated. |
| `auth.reset_password_wrong` | 403 | That password doesn't match. | Wrong password on the reset endpoint — distinct from `invalid_credentials` because the user JUST typed their current password and deserves a specific message. |

### Validation

| Code | HTTP | Default `user_message` | When |
|---|---|---|---|
| `validation.field_required` | 400 | A required field is missing. | `details.field` lists which one. |
| `validation.field_type` | 400 | A field has the wrong type. | Wrong shape (e.g. expected int, got string). |
| `validation.field_range` | 400 | A field is out of the allowed range. | Min/max/length constraint violated. |
| `validation.payload_malformed` | 400 | The request couldn't be understood. | Body / multipart parse failure. |
| `validation.payload_too_large` | 413 | That request is too large. | Body / attachment exceeds instance limit. |

Validation errors include `details.fields` — an array of
`{field, type, message}` entries — for clients that want to
highlight specific inputs.

### Resource lifecycle

| Code | HTTP | Default `user_message` | When |
|---|---|---|---|
| `resource.not_found` | 404 | That doesn't exist anymore. | Generic 404. Prefer feature-specific codes when available. |
| `resource.conflict` | 409 | Someone changed that before you did — refresh and try again. | Optimistic-concurrency-style conflict. |
| `resource.already_exists` | 409 | That already exists. | Generic uniqueness collision. |

### Rate limiting

| Code | HTTP | Default `user_message` | When |
|---|---|---|---|
| `rate_limit.exceeded` | 429 | You're going too fast. Try again in a moment. | Per-IP bucket exhausted. `retry_after_seconds` populated. Retryable. |
| `rate_limit.ip_blocked` | 403 | Your IP has been blocked by this instance. | IP in the blocked-IPs table. |

### Channels

| Code | HTTP | Default `user_message` | When |
|---|---|---|---|
| `channels.not_found` | 404 | That channel doesn't exist or you don't have access to it. | Channel id missing OR private + not a member. Deliberately conflates the two so private channels don't leak. |
| `channels.access_denied` | 403 | You can't do that in this channel. | Channel member but lacking per-channel privilege. |
| `channels.voice_only_no_text` | 400 | Messages can't be sent to a voice-only channel. | Wrong channel type for the action. |

### Messages

| Code | HTTP | Default `user_message` | When |
|---|---|---|---|
| `messages.not_found` | 404 | That message is gone. | Message id missing — deleted, never existed, or hidden. |
| `messages.too_long` | 400 | That message is too long for this instance. | Exceeds `max_message_length`. `details.limit` carries the ceiling. |
| `messages.empty` | 400 | Add a message or an attachment before sending. | Empty body + no attachments + no stickers. |
| `messages.attachment_too_large` | 413 | Those attachments are too big for this instance. | Combined size over `max_total_attachment_mb`. |
| `messages.timed_out` | 403 | You're in a timeout and can't send messages right now. | `details.until` carries the expiry. |

### Stickers

| Code | HTTP | Default `user_message` | When |
|---|---|---|---|
| `stickers.not_found` | 404 | That sticker doesn't exist. | Sticker id has no matching row. |
| `stickers.not_available` | 404 | That sticker isn't available for use right now. | Sticker deactivated (`is_active=false`). |
| `stickers.alias_taken` | 409 | That sticker shortcode is already in use. | `details.alias` is assigned to another sticker. |
| `stickers.invalid_alias` | 400 | Sticker shortcode must be 2–32 lowercase letters, digits, or underscores. | Alias failed `^[a-z0-9_]{2,32}$`. |
| `stickers.invalid_display_name` | 400 | Sticker name must be 1–64 printable characters. | `display_name` empty / too long / control chars. |
| `stickers.unsupported_type` | 400 | Stickers must be PNG, WebP, GIF, or JPEG. | MIME not in allow-list. |
| `stickers.too_large` | 413 | Stickers must be 512 KB or smaller. | File exceeds `MAX_STICKER_BYTES`. |

### Friends

| Code | HTTP | Default `user_message` | When |
|---|---|---|---|
| `friends.self_relation` | 400 | You can't friend yourself. | Caller targeted themselves. |
| `friends.duplicate_request` | 409 | There's already a friendship or pending request with that user. | Row exists in some state. |
| `friends.not_found` | 404 | Couldn't find that user to add as a friend. | Handle resolution failed OR friendship_id missing. |
| `friends.not_recipient` | 403 | Only the person who received the request can accept it. | Accept attempt by non-addressee. |
| `friends.blocked` | 403 | That user isn't accepting friend requests. | Recipient has caller blocked. Wire-level wording is intentionally vague. |

### Storage / uploads

| Code | HTTP | Default `user_message` | When |
|---|---|---|---|
| `storage.quota_exceeded` | 413 | This instance is out of storage space. | Instance-wide quota hit. |
| `storage.unsupported_type` | 400 | That file type isn't allowed. | MIME not in instance allow-list. |
| `storage.upload_failed` | 500 | Couldn't save that file. Try again in a moment. | Generic upload-pipeline failure. **Retryable.** |

### Federation

| Code | HTTP | Default `user_message` | When |
|---|---|---|---|
| `federation.webfinger_failed` | 404 | Couldn't find that user on the remote instance. | WebFinger returned no actor. |
| `federation.remote_unreachable` | 503 | The remote instance isn't responding right now. | HTTP error reaching remote. **Retryable.** |
| `federation.invalid_handle` | 400 | That looks like an invalid user handle. | Handle parse failure (expected `user@host`). |

### Server / catch-all

| Code | HTTP | Default `user_message` | When |
|---|---|---|---|
| `server.internal_error` | 500 | Something went wrong on the server. The team's been notified. | Unhandled exception. `request_id` is the support key. **Retryable.** |
| `server.unavailable` | 503 | The server is temporarily unavailable. Try again in a moment. | Dependency outage / maintenance mode. **Retryable.** |
| `server.feature_disabled` | 503 | This instance has that feature turned off. | Feature gated and operator-disabled. |

### Client-emitted (never produced by the server)

These codes are produced by clients when a request fails before
reaching the server, OR when the network failure mode needs
distinguishing from a server-side condition. Their `status_code`
in the envelope is `0` (sentinel: no HTTP exchange happened).
Third-party clients should emit these exact strings so cross-tool
telemetry, support flows, and offline-handling stay consistent.

| Code | Status | Default `user_message` | When |
|---|---|---|---|
| `client.network_offline` | 0 | You're offline. Reconnect to keep chatting. | Device-level offline: `navigator.onLine === false` or platform equivalent. ALL instances are unreachable. **Retryable** (resolves when device reconnects). |
| `client.network_timeout` | 0 | The server took too long to respond. Try again in a moment. | Request started but no response in time. Device is online, server is slow. **Retryable.** |
| `client.cors_blocked` | 0 | Your browser blocked this request. The server may be misconfigured. | Browser refused the cross-origin response. Almost always an operator-side `Access-Control-Allow-Origin` misconfig. Not user-recoverable. |
| `instance.unreachable` | 0 | Couldn't reach that instance. It may be offline. | DEVICE is online (other domains work) but this specific instance didn't respond. **Federation-aware**: a remote instance being unreachable is normal and should NOT be surfaced as "you're offline." **Retryable.** |
| `instance.home_unreachable` | 0 | Your home instance is offline. Some features won't work until it's back. | Same root cause as `instance.unreachable` but the affected instance is the user's HOME instance. Surface more prominently — home being down disables most operations, a remote being down disables ONE conversation. **Retryable.** |

**Federation guidance for client developers:**

Federated applications routinely talk to N instances at once: the
viewer's home, plus any joined remote instances, plus federation
peers reached through ActivityPub. Distinguish these states:

| State | Code | UX recommendation |
|---|---|---|
| Device has no internet | `client.network_offline` | Top-of-app banner. Disable composer. Pause WS reconnect. |
| Home instance offline, device fine | `instance.home_unreachable` | Top-of-app banner with home-instance hostname. Most operations will fail until it's back; show this prominently. |
| One joined remote offline, others fine | `instance.unreachable` (scoped to that host) | Per-instance badge on the server rail. DO NOT global-banner this — it's the federation normal-case. Operations against unaffected instances continue. |
| Federation peer reached through home is offline | `federation.remote_unreachable` (server-emitted 503) | Per-conversation inline message. Home is fine, your messages to OTHER conversations still flow. |

## Adding a new error code (server contributors)

1. Pick a dotted name in an existing or new area: `area.condition`.
2. Add the constant to `ErrorCode` in `pufferblow/api/errors/codes.py`.
3. Add an `ErrorSpec(...)` entry to `ERROR_REGISTRY` with status,
   default user message, retry hint, and a one-line `description`.
4. Document the row in the relevant table above. Use the same
   default `user_message` so docs and behaviour can't drift.
5. Migrate the raise site: `raise ApiError(ErrorCode.YOUR_NEW_CODE,
   details={...})`.

Renaming or removing a code is a wire break — bump the API version
or run a parallel deprecation window.
