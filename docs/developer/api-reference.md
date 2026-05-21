# API reference

This page is the hand-written guide for building against the
Pufferblow API. It covers the auth flow, the request and response
shapes you'll hit most, the WebSocket protocol (which is NOT in
the OpenAPI schema), and the conventions that aren't obvious from
reading individual endpoint signatures.

For the exact list of every endpoint and its parameters — which
changes faster than this prose — call the live OpenAPI schema on
a running instance:

!!swagger ./openapi.json!!

The schema is the source of truth for *what* exists; this page is
the source of truth for *how* to use it.

## Audience

You're writing one of:

- A **bot**, a **scripted integration**, or **migration tool**
  against the HTTP API.
- An **alternative client** (web, mobile, terminal) that does what
  the official Electron client does.
- A **server-to-server integrator** — federation, an admin
  dashboard, monitoring.

If you just want to script day-to-day stuff (post messages, react,
manage members), use the [Python SDK](sdk.md) — it wraps the
endpoints below and ships with retry, refresh, and async support.
This page is what you need when the SDK doesn't cover your
use case or you're working in a language without an SDK yet.

## Versioning and stability

- The HTTP API is mounted under `/api/v1/...` for everything
  except voice, which is at `/api/v2/voice/*`. The `v1` path is
  the **only** stable contract path; routes outside that prefix
  (`/storage/...`, `/ws`, `/.well-known/...`, federation paths)
  are also part of the public surface but follow their own
  semantics (described below).
- The current line is `1.0`. Breaking changes between 1.x point
  releases get an explicit deprecation note in the release notes.
- The OpenAPI schema served at `/openapi.json` always reflects
  the code the server is actually running. If your client cares
  about a specific field's presence, snapshot the schema at
  build time and lint against it in CI.

## Base URL

Every Pufferblow instance lives at its own hostname + port. The
default port is `7575`. Example for a self-hosted instance at
`chat.example.com:7575`:

```
https://chat.example.com:7575/api/v1/users/signin?username=alice&password=...
```

There is no central directory. Federated peers are discovered
via [WebFinger](#federation) and [ActivityPub actors](#federation),
not by querying a registry.

## Authentication

Pufferblow uses **bearer-style auth tokens** issued by the home
instance at signup or signin. Every authenticated request includes
the token in one of three places, in this order of preference:

1. `Authorization: Bearer <auth_token>` header — preferred for
   HTTP clients that can set headers.
2. `auth_token` field in the JSON / form body — used by most
   write endpoints because FastAPI parses the body for free; the
   route's Pydantic model declares the field as required.
3. `?auth_token=...` query string — supported on GET endpoints
   that don't carry a body (`/users/signin`, `/users/list`).
   Avoid this in logged URLs.

Tokens are opaque to the client. They look like base64-ish strings
and should be treated as secrets — never embed one in a URL you
intend to share, never log one server-side.

### Signing up

```
POST /api/v1/users/signup
Content-Type: application/json

{
  "username": "alice",
  "password": "correct-horse-battery-staple"
}
```

Response on success:

```json
{
  "status_code": 201,
  "message": "Account created successfully",
  "auth_token": "<access-token>",
  "refresh_token": "<refresh-token>",
  "token_type": "Bearer",
  "auth_token_expire_time": "2026-05-22T12:00:00Z",
  "refresh_token_expire_time": "2026-08-19T12:00:00Z"
}
```

Failure modes:

- `409 Conflict` — username already exists on this instance.
- `503 Service Unavailable` — the operator hasn't run
  `pufferblow setup` yet.

### Signing in

```
GET /api/v1/users/signin?username=alice&password=correct-horse-battery-staple
```

Signin is a **GET with query params** for historical reasons —
client libraries should still treat the password as sensitive
(don't accidentally log the full URL). Response shape matches
signup.

Failure modes:

- `401 Unauthorized` — wrong password.
- `403 Forbidden` — account is banned (`detail` says so), or
  belongs to a different instance (federated identity isn't
  portable: see [Federation](#federation)).
- `404 Not Found` — username doesn't exist on this instance.

### Using the token

Three styles, pick whichever the endpoint accepts. For most
write endpoints the body field is the only style supported:

```
POST /api/v1/users/profile
Content-Type: application/json

{ "auth_token": "<access-token>" }
```

The HTTP `Authorization: Bearer ...` header is honored on every
endpoint as a fallback, so clients that send both will work even
if a route only documents the body field.

### Token lifecycle

The access token (`auth_token`) is the short-lived one — minutes
to hours, depending on the instance's `AUTH_TOKEN_EXPIRES_IN`
setting. The refresh token is long-lived (typically 90 days).

When the access token nears expiry, exchange the refresh token
for a new pair:

```
POST /api/v1/auth/refresh
Content-Type: application/json

{ "refresh_token": "<refresh-token>" }
```

Returns a new `auth_token` + `refresh_token` with fresh expiry
timestamps. Old refresh tokens are revoked on use — replay attacks
on a refresh token are detected and revoke the entire session.

### Decentralized (node-to-node) auth

For server-to-server / SDK-to-instance flows that don't have a
human password, Pufferblow ships a challenge-response handshake at
`/api/v1/auth/decentralized/*`:

```
POST /api/v1/auth/decentralized/challenge   → { challenge_id, nonce }
POST /api/v1/auth/decentralized/verify       → { session_token }
POST /api/v1/auth/decentralized/introspect   → { user_id, ... }
POST /api/v1/auth/decentralized/revoke       → { message }
```

The node signs the nonce with its registered public key, the server
verifies, and a node session token is issued in lieu of an
auth_token. Use this when your client is a bot or daemon and you
don't want to keep a long-lived user-flavored token around.

## Common workflows

### Send a text message

```
POST /api/v1/channels/{channel_id}/send_message
Content-Type: multipart/form-data

auth_token=<token>
message=hello world
```

Returns the canonical message object including `message_id`,
`sender_user_id`, `sent_at` (ISO 8601 UTC), `attachments=[]`, and
the sender's profile snapshot fields (`sender_username`,
`sender_avatar_url`, `sender_avatar_lqip_url`, etc.).

Empty messages are rejected (400). The instance's
`max_message_length` setting caps message text (default 50,000
chars).

### Send a message with attachments

Same endpoint, multipart with a repeated `attachments` field:

```
POST /api/v1/channels/{channel_id}/send_message
Content-Type: multipart/form-data

auth_token=<token>
message=look at this
attachments=@photo.jpg
attachments=@notes.pdf
```

The server runs each attachment through the storage pipeline —
content-hash dedup, MIME detection, size limits per type, and
synchronous LQIP generation for images. The response's
`attachments` array carries:

```json
{
  "url": "/storage/<sha256>",
  "lqip_url": "/storage/<sha256>?variant=lqip",
  "filename": "photo.jpg",
  "type": "image/jpeg",
  "size": 184320
}
```

`lqip_url` is `null` for non-images and for files that hit the
generation path before LQIP shipped. Clients should treat its
absence as "render a skeleton until the full image loads."

### Load message history

```
GET /api/v1/channels/{channel_id}/load_messages?auth_token=<token>&limit=50
```

Returns the most recent `limit` messages in reverse chronological
order (newest first). For older history, pass `before=<message_id>`:

```
GET /api/v1/channels/{channel_id}/load_messages?auth_token=<token>&limit=50&before=<msg_id>
```

Each response message includes the sender snapshot, reactions
summary, attachments, and the per-message read state.

### Search messages

```
GET /api/v1/channels/{channel_id}/search?auth_token=<token>&query=hello
```

Server-side scan within the channel. Returns up to ~200 matches
plus a `truncated_scan` flag set when the channel was too big to
scan exhaustively — the client should fall back to local
filtering for live results.

### React to a message

```
POST /api/v1/channels/{channel_id}/messages/{message_id}/reactions
Content-Type: application/json

{ "auth_token": "<token>", "emoji": "🎉" }
```

The emoji can be any 1–32-character Unicode string (including
multi-codepoint sequences like flags + skin tones). The server
keeps a unique `(message_id, user_id, emoji)` tuple so a user
can't double-react with the same emoji. To remove a reaction:

```
DELETE /api/v1/channels/{channel_id}/messages/{message_id}/reactions
```

with the same body shape. Loaded messages carry a `reactions`
array summarizing emoji counts and a `viewer_reacted` boolean per
emoji.

### Manage channels

```
GET    /api/v1/channels/list/                      ← needs auth_token in body
POST   /api/v1/channels/create/                    ← needs `manage_channels` privilege
PUT    /api/v1/channels/{channel_id}/update
DELETE /api/v1/channels/{channel_id}/delete
PUT    /api/v1/channels/{channel_id}/add_user
DELETE /api/v1/channels/{channel_id}/remove_user
```

Channel types are `text`, `voice`, or `mixed`. The
`channel_visibility` field is one of `public`, `private`, or
`hidden` — public channels appear in the channel list to everyone;
private channels only to users explicitly added; hidden channels
are like private but suppressed from the channel sidebar even for
members (used for system / log channels).

### Upload an avatar / banner

```
POST /api/v1/users/profile/avatar
Content-Type: multipart/form-data

auth_token=<token>
file=@avatar.png
```

```
POST /api/v1/users/profile/banner
Content-Type: multipart/form-data

auth_token=<token>
file=@banner.jpg
```

Returns `{ avatar_url, avatar_lqip_url, ... }`. Image is
synchronously deduped, validated, and LQIP-generated; AVIF
optimization happens later in the background. The same flow exists
for server-level branding at `/api/v1/system/upload-avatar` and
`/api/v1/system/upload-banner` — those require the
`manage_server_settings` privilege.

## Real-time: WebSocket protocol

The WebSocket endpoints are **not in the OpenAPI schema** (FastAPI
doesn't include WS routes in the OpenAPI document). Pufferblow
exposes two:

| Endpoint | Purpose |
|----------|---------|
| `/ws`                              | Global session — receives DM updates, presence, notifications. One per signed-in session. |
| `/ws/channels/{channel_id}`        | Channel-scoped — receives messages, reactions, member events for that channel only. Open one per visible channel. |

### Handshake

```
ws://chat.example.com:7575/ws?auth_token=<token>
ws://chat.example.com:7575/ws/channels/<channel_id>?auth_token=<token>
```

`auth_token` MUST be in the query string for the initial upgrade
because browsers don't expose a way to set headers on `new
WebSocket(...)`. After the upgrade, no further auth is sent — the
session is bound to the socket for its lifetime.

### Receiving

Every server-to-client frame is a JSON object with a `type` field
that tells you the event:

```json
{ "type": "message_created", "channel_id": "...", "message": { ... } }
{ "type": "message_updated", "channel_id": "...", "message": { ... } }
{ "type": "message_deleted", "channel_id": "...", "message_id": "..." }
{ "type": "reaction_added",  "message_id": "...", "user_id": "...", "emoji": "🎉" }
{ "type": "reaction_removed", "message_id": "...", "user_id": "...", "emoji": "🎉" }
{ "type": "user_presence",   "user_id": "...", "status": "online" }
{ "type": "user_typing",     "channel_id": "...", "user_id": "..." }
{ "type": "notification",    "notification": { ... } }
```

The `message` shape matches `GET /channels/{id}/load_messages`
exactly. Clients can use the same renderer for both.

### Sending

The client can push only two message kinds upstream:

```json
{ "type": "presence_update", "status": "afk" }
{ "type": "typing", "channel_id": "..." }
```

Anything else is dropped server-side. The presence statuses are
`online`, `idle`, `afk`, `dnd`, and `offline` (the last is
system-set on disconnect, not user-pickable).

### Heartbeats & disconnect

The server sends WebSocket pings every 25 s; the client should
reply with a pong. The server tears down the session if it misses
two consecutive pongs, which flips the user's presence to
`offline` and broadcasts a `user_presence` event to that user's
visible channels. Clients should reconnect with exponential
backoff (start at 1 s, cap at 30 s) on any unexpected close.

## Storage and images

All uploaded files (avatars, banners, attachments) are stored
content-addressed. Two URL patterns exist:

```
GET /storage/{file_hash}                  ← full file
GET /storage/{file_hash}?variant=lqip     ← ~32 px WebP placeholder
```

The hash is SHA-256 of the original bytes. The route is open —
no auth required — because the path itself is unguessable. Server
responses set strong caching headers:

```
Cache-Control: public, max-age=31536000, immutable
ETag: "<hash>"               (or "<hash>-lqip" for the variant)
Last-Modified: <RFC 7231>
```

Conditional requests with `If-None-Match` return `304 Not
Modified` and skip the body. Range requests work for non-LQIP
content so seekable video playback is supported.

LQIP placeholders are public-by-design (rendering a 32 px preview
isn't a confidentiality concern), so they're stored unencrypted
even on instances that enable server-side encryption for
originals.

### LQIP delivery pattern

When a response includes both the full URL and the LQIP URL:

```json
{
  "avatar_url":      "/storage/abc123...",
  "avatar_lqip_url": "/storage/abc123...?variant=lqip"
}
```

A well-behaved client paints the LQIP first (it's typically a few
hundred bytes), then preloads the full image off-DOM and crossfades
once it's decoded. The official client's `<ProgressiveImage>`
component implements this — see the client architecture page if
you're writing an alternative one.

`*_lqip_url` is `null` / absent when the server didn't generate
a placeholder (non-image upload, older row predating LQIP, or
generation failure). Clients should fall back to a skeleton
loader in that case rather than racing to fetch the full image.

## Errors

FastAPI's `HTTPException` is the canonical error shape:

```json
{ "detail": "human-readable message" }
```

Validation errors (Pydantic-rejected requests) return `422
Unprocessable Entity` with a list:

```json
{
  "detail": [
    {
      "loc": ["body", "username"],
      "msg": "ensure this value has at least 3 characters",
      "type": "value_error.any_str.min_length"
    }
  ]
}
```

Clients should handle both `string` and `array` shapes for
`detail`. Common status codes:

| Code | Meaning |
|------|---------|
| 200/201   | Success |
| 304       | Cached storage variant matches your `If-None-Match` |
| 400       | Request body shape was OK but values were invalid (size limit, empty message, etc.) |
| 401       | Missing / invalid / expired auth token |
| 403       | Authenticated but lacking the required privilege (or instance-mismatched account) |
| 404       | Resource doesn't exist on this instance |
| 409       | Conflict (username taken, channel name taken, …) |
| 413       | Upload too large for this instance's policy |
| 422       | Pydantic validation failure — see the array detail |
| 429       | Rate limit (see below) |
| 503       | Instance not initialized, or a required component is offline |

## Rate limiting

Pufferblow ships with a per-IP rate limiter on signin / signup /
refresh routes (it backs onto memcached when configured, falls
through to in-process when not). Excess requests get `429 Too
Many Requests`. Most domain routes (messages, channels) are not
rate-limited at the HTTP layer because they're already gated by
auth + privileges; abuse is handled by the moderation system.

The `Retry-After` header is set on 429s and reflects the
remaining window in seconds. Clients should respect it rather
than retrying aggressively.

## Pagination

Two patterns appear in the API:

- **Cursor-based** — used by `/load_messages` and any other
  feed that grows over time. Pass `before=<id>` to walk
  backwards; the response carries no explicit "next" cursor
  because clients can use the oldest returned `message_id`.
- **Offset-based** — used by admin / control-panel endpoints
  (`/system/recent-activity`, etc.). Pass `limit` and the
  server defaults are documented per endpoint.

There is no per-instance "global" message feed. All message
queries scope to a channel ID — channels are the unit of
pagination.

## Federation

Federation runs over [ActivityPub](https://www.w3.org/TR/activitypub/)
and exposes the standard surface plus a WebFinger discovery hop:

```
GET  /.well-known/webfinger?resource=acct:alice@chat.example.com
GET  /users/{username}                ← actor document
POST /users/{username}/inbox          ← receive activities from peers
GET  /users/{username}/outbox         ← outgoing federated history
POST /shared-inbox                    ← optional aggregated inbox
```

The actor document includes the federation public key and the
`endpoints` block — the same shape Mastodon and other ActivityPub
servers use. Pufferblow doesn't claim full ActivityPub conformance
— follow / unfollow / direct messages work between Pufferblow
instances and to compatible third parties, but channel-scoped
activity does NOT federate (channels are local-only, see the
[Federation operator doc](../operator/federation.md) for the
exhaustive list of what crosses the wire).

Accounts are **locked to the instance they were created on**.
Signing up on `example.org` does not give you an account on
`friend.network`. Cross-instance follow / DM works once you've
discovered the remote actor via WebFinger.

## System endpoints

Useful for clients and dashboards:

```
GET  /api/v1/system/info                ← server name, branding, limits, settings
POST /api/v1/system/recent-activity     ← admin audit log (requires `view_audit_logs`)
POST /api/v1/system/charts/user-status  ← chart data for the control panel
POST /api/v1/system/logs                ← live tail of server logs (`view_audit_logs`)
```

The `/system/info` response is the canonical place to discover an
instance's branding (`server_name`, `avatar_url`, `banner_url`,
their `*_lqip_url` siblings), federation hints, and policy limits
(message length, attachment sizes, allowed extensions per type).
Cache it for a few minutes between calls; nothing in the response
changes per-request.

## Voice

Voice runs over `/api/v2/voice/*` — the V1 path is no longer
served. Endpoints provision SFU sessions, hand out short-lived
TURN credentials, and synchronize participant state. Detailed
flow (including codec selection and DSP recommendations) is in
the [Server architecture](architecture.md) page; the SFU itself
lives in a sibling repo, [media-sfu](https://github.com/PufferBlow/media-sfu).

The voice path is the place where the OpenAPI schema is most
useful — `/docs` on a running instance will show you each
endpoint's exact request body.

## Where to go next

- **[Live Swagger UI](#)** at `/docs` on a running instance —
  the exact endpoint signatures.
- **[Server architecture](architecture.md)** — how the pieces
  hang together: managers, request pipeline, federation flow,
  voice and storage.
- **[Roles & privileges](roles.md)** — which privilege gates
  which route, and how to read the `resolved_privileges` field
  on a profile response.
- **[Python SDK](sdk.md)** — high-level wrapper for the
  endpoints above. Start here if your integration is just
  a bot.
- **[Client (web + desktop)](client.md)** — what the official
  Electron client does on top of the API surface; useful for
  building alternative clients.
