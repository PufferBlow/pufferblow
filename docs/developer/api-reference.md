# API reference

The complete HTTP and WebSocket surface of a Pufferblow instance.
Every public route is listed here with its method, path, request
body, response shape, and required privileges (when any). This
page is the contract; the server source is the implementation.

## Audience

You're writing one of:

- A **bot**, a **scripted integration**, or **migration tool**
  against the HTTP API.
- An **alternative client** (web, mobile, terminal) that does what
  the official Electron client does.
- A **server-to-server integrator** — federation, an admin
  dashboard, monitoring.

If you just want to script day-to-day work (post messages, react,
manage members), use the [Python SDK](sdk.md) — it wraps the
endpoints below and ships with retry, refresh, and async support.
This page is what you need when the SDK doesn't cover your use
case, or you're working in a language without an SDK yet.

## Conventions

### Base URL

Every Pufferblow instance lives at its own hostname and port. The
default port is `7575`. Examples here use `chat.example.com` as
a stand-in:

```
https://chat.example.com/api/v1/...
```

There is no central directory; federated peers are discovered via
WebFinger and ActivityPub actors (see [Federation](#federation)).

### Versioning

- HTTP routes are mounted under `/api/v1/...` for everything
  except voice, which is at `/api/v2/voice/*`.
- The `1.0` line is the current stable contract. Breaking changes
  between 1.x point releases get an explicit note in the release
  notes.
- Internal SFU-to-instance routes (`/api/internal/v1/voice/*`)
  are signed-only and not part of the public surface — they are
  documented at the bottom for completeness, but clients should
  not call them.

### Authentication

Most endpoints require a bearer-style **auth token** issued at
signup or signin. Three ways to present it:

1. `Authorization: Bearer <auth_token>` header — accepted on
   every authenticated route.
2. `auth_token` field in the JSON / form body — used by most
   write endpoints because their request models declare it.
3. `?auth_token=...` query string — supported on GET endpoints
   that don't carry a body (signin, list, etc.). Avoid this in
   logged URLs.

Tokens are opaque secrets. Never embed them in shareable URLs and
never log them server-side.

### Error shape

FastAPI's `HTTPException` is the canonical error shape for handler
errors:

```json
{ "detail": "human-readable message" }
```

Pydantic validation errors (`422 Unprocessable Entity`) return a
list of issues instead:

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

Clients should handle both shapes for `detail`. Common status
codes used across the API:

| Code | Meaning |
|------|---------|
| 200 / 201 | Success |
| 304 | Cached storage variant matches your `If-None-Match` |
| 400 | Body shape was OK but values invalid |
| 401 | Missing / invalid / expired auth token |
| 403 | Authenticated but lacking the required privilege |
| 404 | Resource doesn't exist on this instance |
| 409 | Conflict (username taken, channel name taken, …) |
| 413 | Upload too large for this instance's policy |
| 422 | Pydantic validation failure |
| 429 | Rate-limited; honor `Retry-After` |
| 503 | Instance not initialized, or a component is offline |

### Pagination

Two patterns appear in the API:

- **Cursor-based** — used by `/load_messages`. Pass `page` (1-indexed)
  with `messages_per_page` (1–50) to walk back through history.
- **Offset-based** — used by admin / control-panel endpoints
  (`/system/recent-activity`, ping history, etc.) with `page` +
  `per_page` parameters documented per endpoint.

There is no global "all messages" feed. Message queries always
scope to a channel.

### Rate limiting

Pufferblow rate-limits per IP on the signin / signup / refresh
routes (memcached-backed when configured, in-process fallback
otherwise). Excess requests get `429 Too Many Requests` with a
`Retry-After` header in seconds. Domain routes (messages,
channels) are not HTTP-rate-limited — abuse is handled by the
moderation system.

---

## Core

These four routes live at the root of the server and aren't
prefixed.

### `GET /`

Bare root. Returns a tiny pointer to `/api/v1/info`. Useful as a
health-check ping when you don't have an auth token.

### `GET /api/v1`

Equivalent of the bare root, scoped under the version prefix.

### `GET /api/v1/info`

Lightweight build info (version, commit SHA). No auth required.
Distinct from `/api/v1/system/server-info`, which is the rich
instance descriptor.

### `POST /api/v1/auth/refresh`

Exchange a refresh token for a new access + refresh token pair.

```json
{ "refresh_token": "<refresh-token>" }
```

Response carries the same shape as signin/signup:

```json
{
  "status_code": 200,
  "auth_token": "<new-access>",
  "refresh_token": "<new-refresh>",
  "token_type": "Bearer",
  "auth_token_expire_time": "...",
  "refresh_token_expire_time": "..."
}
```

The old refresh token is revoked on use; reusing it returns 401
and revokes the entire session (replay-attack detection).

### `POST /api/v1/auth/revoke`

Invalidate a refresh token without exchanging it. Use on signout.

```json
{ "refresh_token": "<refresh-token>" }
```

Returns `{ "status_code": 200, "message": "..." }`. Idempotent —
revoking an already-revoked token returns 200, not an error.

---

## Users

All routes under `/api/v1/users`.

### `GET /api/v1/users`

Trivial root-of-section descriptor. Useful for clients that walk
the API to confirm the namespace is mounted.

### `POST /api/v1/users/signup`

Create a new account on this instance. Pufferblow accounts are
LOCAL to the instance — there is no central directory.

```json
{ "username": "alice", "password": "correct-horse-battery-staple" }
```

Response on success (201):

```json
{
  "status_code": 201,
  "message": "Account created successfully",
  "auth_token": "<access>",
  "refresh_token": "<refresh>",
  "token_type": "Bearer",
  "auth_token_expire_time": "2026-05-22T12:00:00Z",
  "refresh_token_expire_time": "2026-08-19T12:00:00Z"
}
```

- 409 — username already exists.
- 503 — operator hasn't run `pufferblow setup` yet.

### `POST /api/v1/users/signin`

Sign in with username + password, sent as a JSON body so the password
never lands in a URL, a proxy log or browser history.

```json
{ "username": "alice", "password": "..." }
```

Response matches signup. Failure modes:

- 400 — an empty `username` or `password` (a `validation.*` error).
- 401 — wrong password **or** unknown username, with the same answer
  (`auth.invalid_credentials`) so a name cannot be probed for.
- 403 — account is banned, or belongs to a different instance.

`GET /api/v1/users/signin?username=&password=` still works for older
clients but is deprecated: it puts the password in the URL.

### `POST /api/v1/users/profile`

Fetch a user's profile metadata. With `user_id` omitted, returns
the caller's own profile (including `is_account_owner: true`).
With `user_id` set, returns the target user's profile.

```json
{ "auth_token": "<token>", "user_id": "<optional-target-id>" }
```

Returns:

```json
{
  "status_code": 200,
  "user_data": {
    "user_id": "...",
    "username": "...",
    "about": "...",
    "avatar_url": "/storage/<hash>",
    "avatar_lqip_url": "/storage/<hash>?variant=lqip",
    "banner_url": "/storage/<hash>",
    "banner_lqip_url": "/storage/<hash>?variant=lqip",
    "avatar_kind": "image",
    "banner_kind": "solid",
    "accent_color": "#3b82f6",
    "avatar_seed": "...",
    "pronouns": "she/her",              // null when not set
    "custom_status": "grinding to Phantom",  // null when not set
    "profile_settings": { ... },        // see "Profile customisation"; always complete
    "status": "online",
    "roles_ids": [...],
    "resolved_roles": [...],
    "resolved_privileges": [...],
    "moderation_state": { ... },
    "created_at": "...",
    "updated_at": "...",
    "last_seen": "..."
  }
}
```

`*_lqip_url` is null when the file has no placeholder (older
upload, non-image, or LQIP generation failure). See the
[Storage](#storage) section for the LQIP pattern.

### `PUT /api/v1/users/profile`

Edit one field of the caller's profile per request. The request
body carries an `auth_token` plus exactly one of the editable
fields:

```json
{
  "auth_token": "<token>",
  "new_username": "alice2",      // optional
  "status": "afk",               // one of: online, idle, afk, dnd
  "new_password": "...",         // requires `old_password`
  "old_password": "...",
  "about": "Lover of mango pickle.",   // at most 190 characters
  "pronouns": "she/her",               // at most 40; "" clears it
  "custom_status": "grinding to Phantom"  // at most 60; "" clears it
}
```

Returns `{ "status_code": 200, "message": "..." }`. The route
short-circuits on the first set field, so to update both username
AND bio, call it twice. `pronouns` and `custom_status` may be sent
together (or one at a time); an omitted one is left alone and `""`
clears it. Text is trimmed.

- 409 — new username already taken.
- 401 — `old_password` doesn't match (for password changes).
- 400 (`validation.field_range`) — `about`, `pronouns` or `custom_status`
  is over its limit; `details` carries `field` and `max`.

### `POST /api/v1/users/profile/avatar`

Upload a new avatar. Multipart form upload:

```
auth_token=<token>
file=@avatar.png
```

Response (201):

```json
{
  "status_code": 201,
  "message": "Avatar uploaded successfully",
  "avatar_url": "/storage/<hash>",
  "avatar_lqip_url": "/storage/<hash>?variant=lqip",
  "duplicate_status": "new"          // or "existing" if dedup hit
}
```

The image is deduped by content hash, validated, a 32 px WebP
LQIP is generated synchronously, and AVIF optimization is queued
for the background. Size + extension limits come from the
instance's `max_image_size_mb` / `allowed_images_extensions`
settings.

### `POST /api/v1/users/profile/banner`

Same shape as the avatar route, for the user's banner. Response
carries `banner_url` + `banner_lqip_url`.

### `PUT /api/v1/users/profile/appearance`

Switch avatar / banner mode without uploading a new file, shuffle the
default art, or pick a new accent color.

```json
{
  "auth_token": "<token>",
  "avatar_kind": "identicon",  // the default art, or "image" (an upload)
  "banner_kind": "default",    // the default art, "solid" (accent colour only), or "image"
  "accent_color": "#3b82f6",
  "shuffle_avatar_seed": true,  // pick different default art
  "profile_settings": { "frame": "spines", "sections": { "accounts": true } }
}
```

All fields are optional; only the ones present change. The response
carries the resulting `avatar_url` / `banner_url`, which always match
the kinds: `identicon` / `default` write the hosted default image into
the URL, `solid` clears `banner_url`, and `image` is only honoured while
there is an upload to go back to. See
[Default avatars and banners](#default-avatars-and-banners).

#### Profile customisation

`profile_settings` is the one surface a person is allowed to paint. Every
option is a choice from a short list (never free text or a free colour), so
any client can render a profile and none can be made unreadable. Send only
the keys that change; `sections` merges one section at a time. A person who
chose nothing has the defaults, and `profile_settings` in a profile is
always the complete object.

| Key | Values | Default |
| --- | --- | --- |
| `expression` | the face the avatar wears: `default`, `happy`, `wink`, `sleepy`, `surprised`, `grumpy`, or `null` (derive it from the handle) | `null` |
| `frame` | `none`, `ring`, `spines`, `bubbles` (drawn around the avatar) | `none` |
| `tone` | `brass`, `coral`, `rose`, `violet`, `sky`, `sage`, or `null` (derive it from the handle) | `null` |
| `tone2` | same as `tone`; the second colour of a `duo` card or banner | `null` |
| `card_theme` | `mono` (no tint), `tinted` (the colour mixed into the card), `duo` (fading into `tone2`) | `mono` |
| `banner_pattern` | `ripple`, `burst`, `halftone`, `crowd`, `duo` (a gradient from `tone` to `tone2`), or `null` (derive it from the handle). An uploaded banner is `banner_kind: "image"`. | `null` |
| `name_font` | `marcellus`, `barlow`, `condensed` | `barlow` |
| `motion` | `puff`, `still` (whether the avatar moves on hover) | `puff` |
| `sections` | `{ play, mains, accounts, badges }`, each `true`/`false` | play, mains, badges on |

Choosing an `expression` or a `tone` also moves the hosted default art: while
the avatar is the default art (`avatar_kind: "identicon"`), `avatar_url` becomes
the matching `/assets/avatars/pb-avatar-<expression>-<tone>.svg` (and a default
banner takes the `tone`), so a client that knows nothing about profile settings
still shows the face and colour that were chosen. An uploaded picture is never
replaced, and clearing the choice (`null`) returns to the art the account was
given. Clients mix the chosen colour into a dark card at a low, fixed strength, so
white text stays readable whatever is chosen. The update is all-or-nothing:
an unknown key or a value outside its list is a 400 (`validation.field_range`)
whose `details.field` names it (`sections.play`, `tone`, ...), and nothing is
saved, including any `accent_color` or kind sent with it.

#### Default avatars and banners

Every user and server has an `avatar_url` and `banner_url` from the moment
it exists. Until someone uploads their own, they point at images the
instance hosts itself, picked from the id (12 tones x 6 expressions; a
banner shares its avatar's tone). They are plain files, so any client,
official or not, shows them by following the URL it is given:

```
GET /assets/avatars/pb-avatar-<expression>-<tone>.svg   (or .png, 512 px)
GET /assets/banners/pb-banner-<expression>-<tone>.svg   (or .png, 1500x500)
```

No credential is needed. The files are immutable and cached for a year.
Like `/storage/<hash>` paths, the URLs are relative to the instance;
join them to its origin. Tones: ink, graphite, slate, ash, silver, paper,
brass, coral, rose, violet, sky, sage. Expressions: default, happy, wink,
sleepy, surprised, grumpy. Existing accounts and servers are filled in on
the first start after an upgrade.

### `POST /api/v1/users/profile/reset-auth-token`

Force-rotate the user's auth + refresh tokens. Existing tokens
are revoked. The new pair is returned in the same shape as signin.

```json
{ "auth_token": "<current>", "password": "<password>" }
```

Use after a suspected token leak or as part of a password change.

### `GET /api/v1/users/list`

List every user on this instance. Auth token can be in the body
or query.

```
GET /api/v1/users/list?auth_token=<token>
```

Returns:

```json
{
  "status_code": 200,
  "users": [
    { "user_id": "...", "username": "...", "avatar_url": "...", ... },
    ...
  ]
}
```

Each user entry follows the profile shape but omits the moderation
state for non-self viewers. The list is unpaginated — instances
expecting more than a few thousand active users should reach for a
search endpoint instead.

### `GET /api/v1/users/joined-servers`

List the federated peers the caller is following.

```
GET /api/v1/users/joined-servers?auth_token=<token>
```

Returns `{ "status_code": 200, "servers": [...] }`. Each server
entry has `server_id` (host:port), `server_name`, `avatar_url`,
`is_home_instance`.

### `POST /api/v1/users/joined-servers`

Follow a remote Pufferblow instance.

```json
{ "auth_token": "<token>", "target": "chat.friend.example:7575" }
```

Accepts forms with or without `http(s)://` prefix; the home
instance probes the peer for reachability before persisting. On
failure returns a structured `code`:

- `unreachable` — couldn't reach that host.
- `not_pufferblow` — host answered but isn't a Pufferblow instance.
- `self_join` — that's your own home instance.
- `invalid_target` — address looks malformed.

### `POST /api/v1/users/joined-servers/leave`

Unfollow a remote instance.

```json
{ "auth_token": "<token>", "target": "chat.friend.example:7575" }
```

---

## Channels

All routes under `/api/v1/channels`.

### `GET /api/v1/channels`

Trivial root-of-section descriptor.

### `POST /api/v1/channels/list/`

List channels visible to the caller.

```json
{ "auth_token": "<token>" }
```

Returns:

```json
{
  "status_code": 200,
  "channels": [
    {
      "channel_id": "...",
      "channel_name": "general",
      "channel_type": "text",      // or "voice" / "mixed"
      "is_private": false,
      "messages_count": 1234,
      "members_count": 17,
      "channel_visibility": "public",
      "category_id": null,          // the category it sits in, or null
      "position": 0,                // its order within the category, smallest first
      "topic": null,                // one line about what it is for, or null
      "created_at": "..."
    }
  ]
}
```

Members of private channels see them; non-members don't. Hidden
channels never appear in this list.

### `GET /api/v1/channels/read-history`

Return the caller's per-channel last-read marker for every
channel they belong to. Used by the unread badge logic.

```
GET /api/v1/channels/read-history?auth_token=<token>
```

Returns `{ "status_code": 200, "read_history": { "<channel_id>": "<last_read_message_id>", ... } }`.

### `POST /api/v1/channels/create/`

Create a new channel. Requires the `manage_channels` privilege.

```json
{
  "auth_token": "<token>",
  "channel_name": "announcements",
  "is_private": false,
  "channel_type": "text"          // text | voice | mixed
}
```

Returns:

```json
{
  "status_code": 200,
  "message": "Channel created successfully",
  "channel_data": { "channel_id": "...", "channel_name": "...", ... }
}
```

### `PUT /api/v1/channels/{channel_id}/update`

Edit a channel's name, privacy, topic or place. Channel type CANNOT be
changed in place — delete and recreate to switch text ↔ voice.

```json
{
  "auth_token": "<token>",
  "channel_name": "new-name",    // optional
  "is_private": true,            // optional
  "topic": "Patch talk",         // optional, at most 256 characters; "" clears it
  "category_id": "<id>",         // optional; null or "" takes it out of its category
  "position": 2                  // optional; its order within the category
}
```

Requires `edit_channels`. Only the fields present change (a missing `category_id`
leaves the category alone; an explicit `null` removes it). An unknown category is
a 404. The `channel.updated` event carries the new `topic`, `category_id` and
`position`.

### Categories

Categories group channels in the sidebar ("Information", "Community"). They are
instance-wide; a channel points at one with `category_id`. Anyone signed in can
read them; changing them needs `edit_channels`.

| Route | What it does |
| --- | --- |
| `GET /api/v1/channels/categories?auth_token=` | `{ categories: [{ category_id, name, position }] }`, in order |
| `POST /api/v1/channels/categories` `{auth_token, name}` | Add one at the end (201). `name` is trimmed, 1-64 characters, unique (409 if taken) |
| `PUT /api/v1/channels/categories/{category_id}` `{auth_token, name}` | Rename (404 if unknown, 409 on a clash) |
| `PUT /api/v1/channels/categories/order` `{auth_token, category_ids}` | Put these first, in this order; any not named keep their order after them |
| `DELETE /api/v1/channels/categories/{category_id}?auth_token=` | Delete. Its channels stay, uncategorised |

Categories are not announced over the socket: clients read them again when they
open the channel list.

### Pins

A channel keeps a short list of pinned messages (at most 50).

| Route | What it does |
| --- | --- |
| `GET /api/v1/channels/{channel_id}/pins?auth_token=` | `{ pins: [...], limit }`: the pinned messages, newest pin first, each in the usual message shape plus `pinned_by` and `pinned_at`. Anyone who can read the channel can read its pins |
| `PUT /api/v1/channels/{channel_id}/messages/{message_id}/pin?auth_token=` | Pin a message. Needs `moderate_content`. Idempotent (`already: true` the second time); 404 if the message is not in this channel; 409 when the channel already has 50 |
| `DELETE /api/v1/channels/{channel_id}/messages/{message_id}/pin?auth_token=` | Unpin. Needs `moderate_content`. Idempotent (`removed: false` the second time) |

Pinning and unpinning send a `channel.updated` event with
`data.pin = { message_id, pinned }`. Deleting a message unpins it.

### `DELETE /api/v1/channels/{channel_id}/delete`

Delete a channel. Body is empty; auth in header or query.
Requires `manage_channels`.

### `PUT /api/v1/channels/{channel_id}/add_user`

Add a user to a private channel.

```json
{ "auth_token": "<token>", "target_user_id": "<user-id>" }
```

Returns 200 on success, 404 if the user or channel doesn't exist,
403 if the caller lacks `manage_channels`.

### `DELETE /api/v1/channels/{channel_id}/remove_user`

Remove a user from a private channel. Same body shape as
`add_user`.

### `POST /api/v1/channels/{channel_id}/join-audio`

Provision a voice session for the caller in a voice/mixed
channel. Returns:

```json
{
  "status_code": 200,
  "channel_id": "...",
  "user_id": "...",
  "participants": 3,
  "webrtc_config": { ... },
  "token": "<sfu-join-token>",
  "room_name": "..."
}
```

The `token` is a short-lived SFU join token. The new
`/api/v2/voice/channels/{channel_id}/sessions` route is the
preferred entry point for modern clients (see [Voice](#voice)).

### `POST /api/v1/channels/{channel_id}/leave-audio`

Leave the voice session in the channel. Body:

```json
{ "auth_token": "<token>" }
```

### `GET /api/v1/channels/{channel_id}/voice-status`

Snapshot of voice participants in a channel:

```
GET /api/v1/channels/{channel_id}/voice-status?auth_token=<token>
```

Response:

```json
{
  "status_code": 200,
  "channel_id": "...",
  "room_name": "...",
  "participants": [...],
  "participant_count": 3
}
```

---

## Federation peers

Admins and the owner decide which instances this one federates with. All routes need an admin token.

- **Mode** (`open`, `allowlist`, `closed`): open lets anyone federate unless blocked, allowlist only approved
  peers (new hosts show up as `pending`), closed nobody.
- **Status** per peer: `federating`, `pending`, `limited`, `blocked`.
- **Switches** per peer: `media`, `voice`, `discover`. They follow the status unless set by hand. Only `media`
  is enforced today (attachments from a peer with it off are dropped); `voice` and `discover` are recorded.

Activities from, and deliveries to, a refused host are not processed (the inbox answers 403).

| Route | What it does |
| --- | --- |
| `GET /api/v1/federation/peers?auth_token=` | `{ mode, modes, counts, peers: [{ host, status, policy, policy_overrides, software, version, users, follows, last_activity, last_delivery_at, last_delivery_ok, latency_ms, ... }] }` |
| `PUT /api/v1/federation/mode` `{auth_token, mode}` | Set the mode |
| `POST /api/v1/federation/peers` `{auth_token, host, status?}` | Add a host (default `federating`). 201; 409 if it is already a peer. `host` may be a URL; it is reduced to host[:port] |
| `PUT /api/v1/federation/peers/{host}/status` `{auth_token, status}` | Accept, limit, block or set pending (404 if unknown) |
| `PUT /api/v1/federation/peers/{host}/policy` `{auth_token, policy: {media?, voice?, discover?}}` | Set switches by hand |
| `DELETE /api/v1/federation/peers/{host}?auth_token=` | Forget the peer |
| `POST /api/v1/federation/peers/{host}/refresh` `{auth_token}` | Read the peer's nodeinfo (software, version, users). Never contacts a private address |
| `POST /api/v1/federation/peers/import` `{auth_token, hosts, status?}` | Add up to 500 hosts (default `blocked`). Returns `{added, skipped, invalid}`; known hosts keep what they have |

Each change is written to the audit log.

## Messages

All routes under `/api/v1/channels/{channel_id}` (mounted as a
sub-router so messages are always channel-scoped).

### `GET /api/v1/channels/{channel_id}/load_messages`

Page through channel history, newest-first.

```
GET /api/v1/channels/{channel_id}/load_messages
  ?auth_token=<token>&page=1&messages_per_page=20
```

`messages_per_page` is bounded 1–50 (default 20). Returns:

```json
{
  "status_code": 200,
  "messages": [
    {
      "message_id": "...",
      "channel_id": "...",
      "sender_user_id": "...",
      "message": "hello world",
      "sent_at": "2026-05-21T08:30:00Z",
      "attachments": [
        {
          "url": "/storage/<hash>",
          "lqip_url": "/storage/<hash>?variant=lqip",
          "filename": "photo.jpg",
          "type": "image/jpeg",
          "size": 184320
        }
      ],
      "reactions": [
        { "emoji": "🎉", "count": 3, "viewer_reacted": true, "user_ids": [...] }
      ],
      "username": "...",
      "sender_username": "...",
      "sender_avatar_url": "/storage/<hash>",
      "sender_avatar_lqip_url": "/storage/<hash>?variant=lqip",
      "sender_banner_url": "...",
      "sender_banner_lqip_url": "...",
      "sender_status": "online",
      "sender_roles": [...],
      "sender_about": "...",
      "sender_last_seen": "...",
      "sender_created_at": "..."
    }
  ]
}
```

The sender profile is embedded inline so clients don't need a
follow-up `/users/profile` per message.

### `GET /api/v1/channels/{channel_id}/search`

Server-side message search within a channel.

```
GET /api/v1/channels/{channel_id}/search
  ?auth_token=<token>&query=hello
```

Returns:

```json
{
  "status_code": 200,
  "messages": [ ... ],
  "query": "hello",
  "scanned": 8243,
  "truncated_scan": false
}
```

Scans up to ~200 matches. When `truncated_scan` is `true`, the
channel was too large to scan exhaustively — clients should fall
back to local filtering for completeness.

### `POST /api/v1/channels/{channel_id}/send_message`

Send a text message, with optional attachments. Multipart form:

```
auth_token=<token>
message=look at this
sent_at=2026-05-21T08:30:00Z       // optional client-set ISO timestamp
attachments=@photo.jpg              // repeated for multiple files
attachments=@notes.pdf
attachment_descriptions=["A sunset over the bay", ""]   // optional: one text per file, same order
```

`attachment_descriptions` is a JSON list of strings, one for each file in `attachments` and in the same order
(alt text: what the file shows). Each is trimmed and cut to 1000 characters; an entry that is empty or not a
string, a missing list, or text that is not JSON simply means no description. A described file comes back with a
`description` on its attachment object; one without has no such key.

Returns the canonical message object including dedup-resolved
attachment URLs, sender profile snapshot, and the message's
`message_id`. Validation:

- 400 — message empty AND no attachments.
- 400 — message exceeds the instance's `max_message_length`.
- 413 — attachment(s) over the per-file or per-message limit.

### `PUT /api/v1/channels/{channel_id}/mark_message_as_read`

Update the caller's read marker for the channel.

```
PUT /api/v1/channels/{channel_id}/mark_message_as_read?auth_token=<token>&message_id=<msg-id>
```

Idempotent. Used by clients on focus / scroll-to-bottom.

### Edit, delete and react (commands only)

The HTTP routes `PATCH .../messages/{message_id}`, `POST` and `DELETE .../messages/{message_id}/reactions`
and `DELETE .../delete_message` were removed. Use the `message.edit`, `message.delete`,
`reaction.add` and `reaction.remove` commands on the socket (see
[`protocol/v1.md`](../protocol/v1.md)). Authorization is unchanged: a message's sender may edit it, and
the sender or anyone with `delete_messages` may delete it.

---

## Notifications

All routes under `/api/v1/notifications`. Notifications are the
per-user inbox of "something happened that you care about" —
mentions, replies, follows, system events.

### `GET /api/v1/notifications/`

List the caller's notifications, newest first.

```
GET /api/v1/notifications/?auth_token=<token>&limit=20&before=<id>
```

Returns:

```json
{
  "status_code": 200,
  "notifications": [
    {
      "notification_id": "...",
      "kind": "mention",                    // or "reply" / "follow" / ...
      "actor_user_id": "...",
      "channel_id": "...",
      "message_id": "...",
      "is_read": false,
      "created_at": "...",
      "data": { ... }
    }
  ]
}
```

### `GET /api/v1/notifications/unread_count`

Just the count.

```
GET /api/v1/notifications/unread_count?auth_token=<token>
```

Returns `{ "status_code": 200, "unread_count": 7 }`.

### `POST /api/v1/notifications/{notification_id}/read`

Mark one notification read. Idempotent.

```json
{ "auth_token": "<token>" }
```

### `POST /api/v1/notifications/read-all`

Mark every unread notification read.

```json
{ "auth_token": "<token>" }
```

### `GET /api/v1/notifications/preferences`

The caller's per-channel notification preferences.

```
GET /api/v1/notifications/preferences?auth_token=<token>
```

Returns a map of `channel_id → { kind, muted_until }`.

### `PUT /api/v1/notifications/preferences/{channel_id}`

Set the caller's preference for a single channel.

```json
{
  "auth_token": "<token>",
  "kind": "all",            // "all" | "mentions" | "muted"
  "muted_until": null        // ISO timestamp, optional
}
```

### `DELETE /api/v1/notifications/preferences/{channel_id}`

Revert to default (per-instance setting).

---

## Reactions

Reactions on channel messages are the `reaction.add` and `reaction.remove` socket commands
(see [`protocol/v1.md`](../protocol/v1.md)).

---

## Moderation

All routes under `/api/v1/moderation`. Privilege requirements
listed per endpoint.

### `POST /api/v1/moderation/reports/messages`

Report one or more messages for moderator attention.

```json
{
  "auth_token": "<token>",
  "message_ids": ["<msg-1>", "<msg-2>"],
  "category": "harassment",                // free-form, 1–100 chars
  "description": "context"                  // optional, ≤500 chars
}
```

Returns 201. Any signed-in user can report.

### `POST /api/v1/moderation/reports/users`

Report a user.

```json
{
  "auth_token": "<token>",
  "target_user_id": "<user-id>",
  "category": "spam",
  "description": "..."
}
```

### `POST /api/v1/moderation/users/{target_user_id}/ban`

Ban a user from the home instance. Requires `ban_users`.

```json
{ "auth_token": "<token>", "reason": "repeated TOS violations" }
```

Returns 201 with the new moderation state for the target.

### `DELETE /api/v1/moderation/users/{target_user_id}/ban`

Unban. Requires `ban_users`.

```json
{ "auth_token": "<token>" }
```

### `POST /api/v1/moderation/users/{target_user_id}/timeout`

Apply a communication timeout. Requires `mute_users`.

```json
{
  "auth_token": "<token>",
  "duration_minutes": 60,            // 1 – 40320 (28 days)
  "reason": "cooling-off"
}
```

### `DELETE /api/v1/moderation/users/{target_user_id}/timeout`

Lift the timeout early. Requires `mute_users`.

### `POST /api/v1/moderation/reports`

List moderation reports. Requires `view_audit_logs`.

```json
{ "auth_token": "<token>", "limit": 100 }
```

Returns recent reports with their status and target.

### `POST /api/v1/moderation/reports/{report_id}/resolve`

Resolve a report. Requires `moderate_content`.

```json
{
  "auth_token": "<token>",
  "action": "deleted_message",     // free-form action label
  "reason": "..."
}
```

---

## Storage

Content-addressed file storage. The full surface is split into
admin / upload endpoints and a public-read endpoint.

### `POST /api/v1/storage/upload`

Generic upload entry point. Multipart form:

```
auth_token=<token>
file=@anything.bin
```

Auto-categorizes by MIME (avatars, banners, images, videos, etc.)
and applies the per-category size + extension limits. Returns:

```json
{
  "status_code": 201,
  "url": "/storage/<hash>",
  "filename": "anything.bin",
  "type": "...",
  "size": 12345,
  "is_duplicate": false
}
```

Most clients should use the domain-specific upload routes instead
(`/profile/avatar`, `/system/upload-avatar`, `/send_message` with
attachments) so the file gets linked to the right reference type.

### `POST /api/v1/storage/files`

List files in a storage subdirectory. Requires
`manage_storage`.

```json
{ "auth_token": "<token>", "directory": "uploads" }
```

### `POST /api/v1/storage/file-info`

Inspect a single file by URL. Requires `manage_storage`.

```json
{ "auth_token": "<token>", "file_url": "/storage/<hash>" }
```

### `POST /api/v1/storage/delete-file`

Delete a file. Requires `manage_storage`. Reference-counted —
the actual file is only removed when all references are dropped.

```json
{ "auth_token": "<token>", "file_url": "/storage/<hash>" }
```

### `POST /api/v1/storage/cleanup-orphaned`

Sweep files that have lost every reference. Requires
`manage_storage`.

```json
{ "auth_token": "<token>", "subdirectory": "uploads" }
```

### `GET /storage/{file_hash}`

Serve a file by its SHA-256 content hash. Public — no auth
required (the path itself is unguessable).

```
GET /storage/<hash>
GET /storage/<hash>?variant=lqip      ← low-quality placeholder
```

Caching headers:

```
Cache-Control: public, max-age=31536000, immutable
ETag: "<hash>"                        ← "<hash>-lqip" for the variant
Last-Modified: <RFC 7231>
```

Conditional `If-None-Match` requests return 304. Range requests
work on the original (non-LQIP) so seekable video playback works.

LQIP placeholders are unencrypted even when the original is —
rendering a 32 px blurred preview is public-by-design.

---

## System

Server-info, branding, telemetry, audit log. All routes under
`/api/v1/system` (mounted via the parent system router).

### `GET /api/v1/system/server-info`

The canonical "what does this instance look like" descriptor.

```
GET /api/v1/system/server-info
```

Returns:

```json
{
  "server_id": "chat.example.com:7575",
  "server_name": "Example Chat",
  "server_description": "...",
  "version": "1.0.0",
  "is_private": false,
  "creation_date": "...",
  "avatar_url": "/storage/<hash>",
  "avatar_lqip_url": "/storage/<hash>?variant=lqip",
  "banner_url": "/storage/<hash>",
  "banner_lqip_url": "/storage/<hash>?variant=lqip",
  "welcome_message": "...",
  "members_count": 42,
  "online_members": 17,
  "max_message_length": 50000,
  "max_image_size": 5,
  "max_video_size": 50,
  "max_sticker_size": 5,
  "max_gif_size": 10,
  "allowed_image_types": ["png", "jpg", ...],
  "allowed_video_types": [...],
  "allowed_file_types": [...],
  "rtc_media_quality": { ... }
}
```

No auth required. Clients should cache this for a few minutes —
the fields don't change per-request.

### `PUT /api/v1/system/server-info`

Edit the instance's name / description / welcome message / policy. Requires
`manage_server_settings`. `welcome_message` (at most 500 characters, trimmed) is the
greeting new members get.

```json
{
  "auth_token": "<token>",
  "server_name": "...",
  "server_description": "...",
  "is_private": false,
  "max_users": 1000,
  "max_message_length": 50000,
  "max_image_size": 5,
  "allowed_image_types": ["png", "jpg"],
  ...
}
```

Only the fields you send are touched. Omit a field to leave it
alone.

### `PUT /api/v1/system/server-appearance`

Switch server avatar / banner mode without uploading. Same shape
and URL handling as the per-user `profile/appearance` route (including
the hosted default art). Requires `manage_server_settings`.

`look` is a partial object of how the server is drawn, every part a choice
from a short list (nothing else is accepted, and an update is all or nothing):

| key | values |
| --- | --- |
| `icon_style` | `initials`, `crop`, `bubble`, `school` |
| `tone`, `tone2` | `brass`, `coral`, `rose`, `violet`, `sky`, `sage` |
| `banner_pattern` | `ripple`, `burst`, `halftone`, `crowd`, `duo` |

`null` puts a setting back to the one derived from the server's id, which is what
clients draw until the owner chooses. The reply and `GET /system/server-info` carry
the whole `look` object. A bad value is a 400 whose `details.field` names it.

### `GET /api/v1/system/instance-health`

Liveness probe. Returns `{ "status_code": 200, "status": "ok",
"components": { ... } }`. No auth required — useful for
monitoring. The `realtime` object reports the open socket count and
the protocol counters (connections, commands by outcome, latency,
rate limiting, delivery); each counter is described in
[Commands and events](../architecture/commands-and-events.md#observability).

### `GET /api/v1/system/health?auth_token=`

The detailed health of the instance, for its admins (the status page).
`/healthz` and `instance-health` stay the small answers anyone can ask; this
one adds what an operator needs, and is refused (403) to everyone else.

```json
{
  "status_code": 200,
  "health": {
    "status": "ok",                      // everything in /healthz, plus:
    "version": "0.9.2",
    "instance": "switchyard.works",
    "uptime_s": 2591204,                 // of this process
    "checks": {                          // database, storage, realtime, and voice when it is enabled
      "database": { "status": "ok", "ms": 4.1, "note": "Answering queries" }
    },
    "latency": {                         // real requests; health checks and static assets are not counted
      "p50": 12.0, "p95": 88.0, "samples": 4021, "window_seconds": 3600,
      "series": [{ "t": 1792000000, "count": 310, "p50": 11, "p95": 90 }]   // 5-minute buckets, last 24 h
    },
    "resources": { "cpu": 23.5, "memory": 61.2, "disk": 48.0 },             // null without psutil
    "uptime_days": [{ "day": "2026-10-20", "checks": 1440, "ratio": 0.9993 }],  // 90 days; ratio null = not watched
    "uptime_percent": 99.98,
    "incidents": [{ "incident_id": "...", "title": "Trouble with database", "state": "resolved", "started_at": "...", "ended_at": "..." }],
    "peers": [{ "host": "mesh.garden", "follows": 2, "last_activity": "..." }]
  }
}
```

The instance checks itself once a minute. Each check counts toward the day it
happened on (a check "works" when nothing in `status` is degraded), and an
incident opens when a check finds something wrong and resolves when one passes
again. Latency lives in memory and starts again with the process; the uptime
days and incidents are stored. `peers` are the instances linked by an accepted
follow: delivery queues and reachability are not tracked, and the health check
never dials out to other instances.

### `GET /api/v1/system/server-stats`

Public counters: users registered, channels, messages. No auth.

### `POST /api/v1/system/server-usage`

CPU / RAM / storage / disk I/O. Requires `view_audit_logs`.

```json
{ "auth_token": "<token>" }
```

### `POST /api/v1/system/upload-avatar`

Upload the server avatar. Multipart form with `auth_token` +
`avatar` file. Requires `manage_server_settings`. Response shape
matches the per-user avatar route. Uploading switches the server's
`avatar_kind` to `image`; `PUT /system/server-appearance` with
`avatar_kind: "identicon"` goes back to the default art. Animated GIF
and WebP are kept as uploaded (they are not re-encoded to a still).

### `POST /api/v1/system/upload-banner`

Upload the server banner. Same shape with `banner` file field; it
sets `banner_kind` to `image` (`"default"` goes back).

### `POST /api/v1/system/runtime-config`

Read the live runtime config (every setting the server reads
from disk plus live overrides). Requires `manage_server_settings`.

```json
{ "auth_token": "<token>", "include_secrets": false }
```

When `include_secrets` is true, sensitive values (DB password,
TURN secret) are included; otherwise they're masked.

### `PUT /api/v1/system/runtime-config`

Update one or more runtime config keys live without a restart.
Requires `manage_server_settings`.

```json
{
  "auth_token": "<token>",
  "settings": {
    "max_message_length": 75000,
    "allowed_images_extensions": ["png", "jpg", "webp"]
  }
}
```

Only keys whitelisted as live-mutable can be set this way. Others
require an env-file edit + restart.

### `GET /api/v1/system/latest-release`

Probe GitHub for the latest pufferblow release. Used by the
client's update banner. No auth required.

### `POST /api/v1/system/server-overview`

Aggregated dashboard data — counters, recent activity excerpt,
storage usage. Requires `view_audit_logs`.

```json
{ "auth_token": "<token>" }
```

### `POST /api/v1/system/activity-metrics`

Aggregated activity buckets (messages per hour, etc.) used by the
control panel. Requires `view_audit_logs`.

### `POST /api/v1/system/logs`

Tail the server's log files. Requires `view_audit_logs`.

```json
{
  "auth_token": "<token>",
  "lines": 200,                           // 1–1000
  "search": "ERROR",                       // optional substring
  "level": "WARNING"                       // DEBUG|INFO|WARNING|ERROR|CRITICAL
}
```

### `POST /api/v1/system/recent-activity`

Audit log of server-wide events (users joining, channels created,
moderation actions, settings changes). Requires `view_audit_logs`.

```json
{ "auth_token": "<token>", "limit": 100 }   // 1 ≤ limit ≤ 500
```

### Stickers and custom emoji

`GET /api/v1/stickers` (any signed-in user) lists the active catalog;
`GET /api/v1/stickers/all` (`manage_stickers`) includes hidden rows;
`POST /api/v1/stickers` (multipart `file`, `display_name`, optional
`alias`, `kind`), `PATCH /api/v1/stickers/{id}` and
`DELETE /api/v1/stickers/{id}` manage it. Each row carries a `kind`:
`sticker` (the default; sent as a message with `sticker_ids`) or
`emoji` (a custom emoji, which **requires** an `alias`, `[a-z0-9_]{2,32}`,
typed as `:alias:` in a message). Either can be used as a reaction with
the key `sticker:<sticker_id>`. Files are at most 512 KB; animated GIF and
WebP are allowed.

### Analytics charts

A family of POST endpoints returning chart-shaped data. Each
takes the same request body — `{ "auth_token": "<token>",
"period": "<period>" }` where period is one of `daily`,
`weekly`, `monthly`, `24h`, `7d`. Each requires `view_audit_logs`
except `user-status`, which only requires authentication.

- `POST /api/v1/system/charts/user-registrations`
- `POST /api/v1/system/charts/message-activity`
- `POST /api/v1/system/charts/online-users`
- `POST /api/v1/system/charts/channel-creation`
- `POST /api/v1/system/charts/user-status`

Each returns `{ status_code, period, data: [...] }` with the
chart series shape documented per endpoint at the route's
docstring level.

### Roles & privileges

All under `/api/v1/system`. See [Roles & privileges](roles.md) for
the conceptual model.

#### `POST /api/v1/system/roles/list`

List all instance roles. Auth required, any signed-in user.

#### `POST /api/v1/system/privileges/list`

List every privilege available for role composition. Auth
required.

#### `POST /api/v1/system/roles`

Create a custom role. Requires `manage_roles`.

```json
{
  "auth_token": "<token>",
  "role_name": "Helper",
  "privileges_ids": ["delete_messages", "mute_users"]
}
```

#### `PUT /api/v1/system/roles/{role_id}`

Update a custom role. Requires `manage_roles`. Same body shape
as create. A `badge` that is left out stays as it is; `"remove_badge": true`
takes it off.

#### Role badges

Every role in the list carries a `badge`: `{ "tier", "tone", "glyph", "image_url"? }`,
or `null`. A person's `resolved_roles` carry the same, so clients can draw the mark
after their name. `tier` is the shape: `staff` (only for a role with `ban_users`,
`mute_users` or `moderate_content`), `community`, or `system` (given by Pufferblow;
it cannot be chosen). `tone` is `brass`, `coral`, `rose`, `violet`, `sky`, `sage`,
`white` or `grey`. `glyph` is one of `crown key shield lifebuoy target star broadcast
brush code heart trophy flame bot check bubbles globe music film gamepad mic`, or
`image` with the `image_url` of an uploaded picture. The built-in Owner, Admin and
Moderator roles are shown with a badge without storing one. At most 50 roles can carry
a badge. Anything else is a `400` whose `details.field` is `badge.<part>`.

```json
{ "auth_token": "<token>", "role_name": "Coach", "privileges_ids": [],
  "badge": { "tone": "violet", "glyph": "target" } }
```

#### `POST /api/v1/system/role-badge-images`

Upload the picture for an image badge. Owner only. Multipart `auth_token` + `file`:
a 128 × 128 PNG under 256 KB. Returns `{ "url": "/storage/<hash>" }` to put in the
badge's `image_url`.

#### `DELETE /api/v1/system/roles/{role_id}`

Delete a custom role. Requires `manage_roles`. Built-in roles
(`owner`, `admin`, `moderator`, `member`) cannot be deleted.

#### `PUT /api/v1/system/users/{target_user_id}/roles`

Replace a user's role assignments. Requires `manage_roles`.

```json
{
  "auth_token": "<token>",
  "roles_ids": ["<role-id-1>", "<role-id-2>"]
}
```

---

## Pings

All routes under `/api/v1/ping`. A "ping" is a low-overhead
hail (think IRC `PRIVMSG` with a single-emoji body) used to
poke a user across instances. Useful as a cheap presence /
reachability test.

### `POST /api/v1/ping/send`

Send a ping to a local or remote user.

```json
{
  "auth_token": "<token>",
  "target": "alice",                       // user_id, username, user@host, or actor URI
  "message": "👋"                          // optional, ≤200 chars
}
```

Returns `{ "status_code": 201, "ping_id": "...", "expires_at": "..." }`.

### `POST /api/v1/ping/instance`

Probe a remote instance for reachability — does NOT require a
target user, just a base URL.

```json
{
  "auth_token": "<token>",
  "target_instance_url": "https://other.example.com"
}
```

Returns the instance's `server-info` if reachable, plus latency.

### `POST /api/v1/ping/ack/{ping_id}`

Acknowledge a received ping.

```json
{ "auth_token": "<token>" }
```

### `GET /api/v1/ping/history`

Paginated history of sent / received pings.

```
GET /api/v1/ping/history
  ?auth_token=<token>&direction=both&page=1&per_page=20
```

`direction` is one of `sent`, `received`, or `both`.

### `GET /api/v1/ping/pending`

List inbound pings that haven't been acknowledged yet.

```
GET /api/v1/ping/pending?auth_token=<token>
```

### `GET /api/v1/ping/stats`

Aggregate ping statistics for the caller (sent total, received,
average latency, etc.).

```
GET /api/v1/ping/stats?auth_token=<token>
```

### `DELETE /api/v1/ping/{ping_id}`

Delete a ping record. The sender can delete their own pings; the
receiver can delete pings sent to them.

```
DELETE /api/v1/ping/<ping_id>?auth_token=<token>
```

---

## Bots

Bots are automated accounts that act for the instance owner and can never do more than the owner can.
Only the **instance owner** manages them. A bot signs in to the realtime socket with its token as
`auth_token` (see [the protocol](../protocol/v1.md#bots)); its token is not accepted by the rest of the HTTP API.

### `POST /api/v1/bots`

Create a bot. The `token` in the response is shown **once** (only a hash is stored) and cannot be recovered.

```json
{ "auth_token": "<owner token>", "name": "greeter", "scopes": ["send_messages"] }
```

`scopes` is any subset of `send_messages` and `view_private_channels` (empty: the bot can read public channels and
do nothing else). Administrative privileges cannot be granted to a bot: asking for one is a 400 that lists the
allowed scopes. A bot's effective privileges are its owner's intersected with its scopes.

Returns `201` with `{ bot: { bot_id, name, owner_user_id, scopes }, token }`.

### `GET /api/v1/bots?auth_token=`

The instance's bots, newest first, revoked ones included: `{ bots: [{ bot_id, name, owner_user_id, scopes,
enabled, revoked, created_at }] }`. Tokens are never returned.

### `DELETE /api/v1/bots/{bot_id}?auth_token=`

Revoke a bot. Its token stops working at once: a connected bot is refused on its next command (and on its next
`ping`), and cannot reconnect. Idempotent (`revoked: false` the second time); an unknown id is a 404.

Non-owners get 403 on all three routes.

---

## Admin

All routes under their explicit paths (no shared prefix).
Operator / instance-admin only.

### `POST /api/v1/blocked-ips/list`

List currently-blocked IP addresses. Requires `manage_blocked_ips`.

```json
{ "auth_token": "<token>" }
```

### `POST /api/v1/blocked-ips/block`

Block an IP. Requires `manage_blocked_ips`.

```json
{
  "auth_token": "<token>",
  "ip": "203.0.113.7",
  "reason": "repeated signin brute-force"
}
```

### `POST /api/v1/blocked-ips/unblock`

Unblock. Same body without `reason`.

### `POST /api/v1/background-tasks/status`

List background tasks and their state (enabled, last run, next
run, success count). Requires `manage_server_settings`.

```json
{ "auth_token": "<token>" }
```

### `POST /api/v1/background-tasks/run`

Run a background task on demand. Requires `manage_server_settings`.

```json
{ "auth_token": "<token>", "task_id": "optimize_unprocessed_images" }
```

### `POST /api/v1/background-tasks/toggle`

Enable or disable a task.

```json
{
  "auth_token": "<token>",
  "task_id": "...",
  "enabled": false
}
```

### `POST /api/v1/background-tasks/backup-config`

Update the database-backup task's configuration. Requires
`manage_server_settings`.

```json
{
  "auth_token": "<token>",
  "enabled": true,
  "mode": "file",                       // "file" | "mirror"
  "path": "/var/backups/pufferblow",
  "mirror_dsn": null,                   // for mode=mirror
  "schedule_hours": 24,
  "max_files": 7
}
```

### `POST /api/v1/background-tasks/backup-config/get`

Read the current backup config.

```json
{ "auth_token": "<token>" }
```

---

## Voice (v2)

All routes under `/api/v2/voice`. The v1 voice path is no longer
served. Audio frames don't traverse the Pufferblow API — they go
to the media-sfu peer the join token grants access to.

### `POST /api/v2/voice/channels/{channel_id}/sessions`

Provision a voice session in a voice/mixed channel.

```json
{
  "auth_token": "<token>",
  "quality_profile": "balanced"            // "low" | "balanced" | "high"
}
```

Returns the SFU join credentials + WebRTC config:

```json
{
  "status_code": 200,
  "session_id": "...",
  "channel_id": "...",
  "join_token": "<sfu-token>",
  "webrtc_config": { ... },
  "room_name": "..."
}
```

### `GET /api/v2/voice/channels/{channel_id}/participants`

List who's currently in the voice session for a channel.

```
GET /api/v2/voice/channels/{channel_id}/participants?auth_token=<token>
```

### `POST /api/v2/voice/sessions/{session_id}/leave`

Leave the voice session.

```json
{ "auth_token": "<token>" }
```

### `GET /api/v2/voice/sessions/{session_id}`

Snapshot of a session's state (participants, mute states,
codec / bitrate hints).

```
GET /api/v2/voice/sessions/<session_id>?auth_token=<token>
```

### `POST /api/v2/voice/sessions/{session_id}/actions`

Apply a participant-level action. The `action` field is a string
verb, the `payload` carries action-specific args.

```json
{
  "auth_token": "<token>",
  "action": "mute",                       // "mute" | "deafen" | "kick" | "quality"
  "payload": { "muted": true }
}
```

`kick` requires the `manage_voice` privilege; `mute`/`deafen` act
on the caller's own state.

---

## Voice calls (1:1)

A call between two people on this instance. Audio goes straight between the two devices
(WebRTC, encrypted with DTLS-SRTP); the instance only relays the set-up messages. Routes are
under `/api/v1/dm-calls`; every request carries `auth_token`.

| Route | What it does |
| --- | --- |
| `POST /api/v1/dm-calls/{callee_id}/invite` `{auth_token, callee_id}` | Ring someone. Returns `{call_id, status: "ringing", ice_servers}`. 404 if there is no such user; 409 if *you* are already on a call or rang this person in the last 5 seconds; 400 if you are calling yourself, or either of you has blocked the other. Someone who is already on a call is not rung, and you are not told: the call rings out like one nobody answered |
| `POST /api/v1/dm-calls/{call_id}/accept` | Callee only. Returns `{status: "accepted", ice_servers}` |
| `POST /api/v1/dm-calls/{call_id}/reject` | Decline, or cancel while it rings |
| `POST /api/v1/dm-calls/{call_id}/end` | End a call |
| `POST /api/v1/dm-calls/{call_id}/signal` `{signal_type, payload}` | Relay one `offer`, `answer`, `candidate` or `relay` (the key exchange for a relayed call) to the other person. The instance does not read `payload`, and refuses one over 32 KB |
| `POST /api/v1/dm-calls/{call_id}/fallback` `{quality_profile?}` | Join a media-sfu session scoped to the call, when a direct connection fails |

`ice_servers` is the STUN/TURN list to give `RTCPeerConnection`.

A call nobody answers within 45 seconds is dropped, and a person whose last realtime connection
closes is taken off their calls (the other person gets `user.dm_call_ended`).

The other person is told over their websocket connection (protocol v1 events):
`user.dm_call_invite {call_id, caller_id}`, `user.dm_call_accepted {call_id}`,
`user.dm_call_rejected {call_id}`, `user.dm_call_ended {call_id}`, and
`user.dm_call_offer` / `user.dm_call_answer` / `user.dm_call_candidate` / `user.dm_call_relay {call_id, from_user_id, payload}`.

### What "end-to-end encrypted" means here

The instance relays the SDP, which carries each side's DTLS certificate fingerprint. If the
instance changed a fingerprint it could sit in the middle of the call. So the official client
signs its SDP and checks the other side's:

- `offer` and `answer` payloads are `{sdp: {type, sdp}, e2ee: {v: 1, key_id, signature, public_key}}`.
- `signature` is an ECDSA P-256 / SHA-256 signature, by the sender's identity key, over the lines
  `pufferblow-call-v1`, `call_id`, the caller's id, the callee's id, `offer` or `answer`, and the
  sender's sorted `a=fingerprint:` values.
- The receiver pins the first key it sees for a person, holds the call and asks when a different
  key appears, and shows a safety number (60 digits from both people's ids and key ids) to compare
  out of band. Without that comparison the first key is trusted on first use.

The instance cannot make a call end-to-end encrypted by itself and does not check any of this; the
guarantee is the clients'.

If the two devices cannot connect directly, both move to the media server (`/fallback`). The server
forwards audio, so the official client seals every encoded audio frame (AES-GCM, `RTCRtpScriptTransform`)
with a key from an ECDH exchange that is signed the same way: each side sends `relay` with
`{relay_key: {v: 1, public_key: <ECDH P-256 JWK>}, e2ee: {...}}`, the signature covering
`pufferblow-call-relay-v1`, the call id, both user ids and the ECDH key. The media server only ever
sees ciphertext. A browser that cannot seal frames does not fall back: the call ends instead of
quietly dropping the encryption.

## Identity keys

The public half of the key a device signs calls with. The instance stores public keys only.

| Route | What it does |
| --- | --- |
| `PUT /api/v1/identity-keys` `{auth_token, public_key, label?}` | Register your key. `public_key` is a P-256 JWK (`kty`, `crv`, `x`, `y`); a private key is refused. Idempotent: `created` is false for a key you already registered. 409 if the key belongs to another account or you already have 10 |
| `GET /api/v1/identity-keys/{user_id}?auth_token=` | A person's keys, oldest first: `{key_id, public_key, label, created_at}`. Any signed-in user can read them |
| `DELETE /api/v1/identity-keys/{key_id}?auth_token=` | Remove one of your own keys. 404 if it is not yours |

`key_id` is the first 32 hex characters of SHA-256 over the 32-byte `x` then the 32-byte `y`.

## ActivityPub & federation

These are the standard ActivityPub endpoints plus a thin Pufferblow
RPC layer for follow / DM convenience.

### `GET /.well-known/webfinger`

Standard WebFinger discovery.

```
GET /.well-known/webfinger?resource=acct:alice@chat.example.com
```

Returns the actor descriptor. No auth required.

### `GET /ap/users/{user_id}`

Actor document for a local user. Includes the federation public
key, inbox URI, outbox URI, and the `endpoints` block. No auth.

### `GET /ap/users/{user_id}/outbox`

Local user's federated outbox (their public ActivityPub
activities). No auth.

### `POST /ap/users/{user_id}/inbox`

Receive a federated activity addressed to a specific local user.
Signature-verified. Returns 202 on acceptance.

### `POST /ap/inbox`

Shared inbox — receive activities addressed to multiple local
users at once. Same signature-verification rules.

### `POST /api/v1/federation/follow`

Convenience wrapper around the ActivityPub Follow activity, for
clients that don't want to construct Follow JSON-LD themselves.

```json
{
  "auth_token": "<token>",
  "remote_handle": "alice@chat.friend.example"
}
```

### `POST /api/v1/dms/send`

Send a DM. Local DMs go through the message system; remote DMs
are wrapped in an ActivityPub Note.

```json
{
  "auth_token": "<token>",
  "peer": "alice",                           // local user_id, username, OR remote handle/URI
  "message": "hello",
  "sent_at": "2026-05-21T08:30:00Z",
  "attachments": ["/storage/<hash>"]
}
```

### `GET /api/v1/dms/messages`

Load the DM conversation with a peer.

```
GET /api/v1/dms/messages?auth_token=<token>&peer=alice&page=1&messages_per_page=20
```

Returns the same message shape as `/load_messages`.

---

## Decentralized auth

Challenge-response handshake for server-to-server / SDK-to-server
authentication where no human password exists. All under
`/api/v1/auth/decentralized`.

### `POST /api/v1/auth/decentralized/challenge`

Step 1: request a challenge for a given node identifier. Requires
an existing `auth_token` so the node can prove identity before
being granted a node session.

```json
{ "auth_token": "<token>", "node_id": "my-bot-1" }
```

Returns `{ "status_code": 200, "challenge_id": "...", "nonce": "..." }`.

### `POST /api/v1/auth/decentralized/verify`

Step 2: send the nonce signed with the node's private key + the
shared secret.

```json
{
  "challenge_id": "...",
  "node_public_key": "<pem>",
  "challenge_signature": "<base64>",
  "shared_secret": "<≥8 chars>"
}
```

Returns `{ "status_code": 200, "session_token": "...", ... }` on
success. The session token replaces the user-flavored auth token
for the node's subsequent requests.

- 401 — signature doesn't verify.
- 410 — challenge expired before verify.

### `POST /api/v1/auth/decentralized/introspect`

Inspect a node session (which user / node, expiry, scope).

```json
{ "session_token": "<token>" }
```

### `POST /api/v1/auth/decentralized/revoke`

Revoke a specific node session.

```json
{ "auth_token": "<token>", "session_id": "..." }
```

---

## WebSocket

Real-time channel. **Not part of the OpenAPI surface** — FastAPI
doesn't include WS routes in the schema, so they're documented
only here.

### `WS /ws`

The single real-time session. Receives channel events, DM updates, presence changes and
notifications, and carries commands. Open one per signed-in session.

```
ws://chat.example.com/ws?auth_token=<token>&protocol=1
```

`protocol=1` is required (the legacy frames and `/ws/channels/{channel_id}` were retired; a
connection without it closes with `1008`). `auth_token` MUST be in the query string for the
initial upgrade because browsers don't expose a way to set headers on `new WebSocket(...)`.
See [`protocol/v1.md`](../protocol/v1.md) for the envelopes, commands and events; the frame
list below is the pre-protocol shape and is kept for history only.

### Server-to-client frames

Every frame is a JSON object with a `type` field:

```json
{ "type": "message_created", "channel_id": "...", "message": { ... } }
{ "type": "message_updated", "channel_id": "...", "message": { ... } }
{ "type": "message_deleted", "channel_id": "...", "message_id": "..." }
{ "type": "reaction_added",   "message_id": "...", "user_id": "...", "emoji": "🎉" }
{ "type": "reaction_removed", "message_id": "...", "user_id": "...", "emoji": "🎉" }
{ "type": "user_presence",    "user_id": "...", "status": "online" }
{ "type": "user_typing",      "channel_id": "...", "user_id": "..." }
{ "type": "notification",     "notification": { ... } }
{ "type": "error",            "error": "..." }
```

The `message` shape matches `GET /load_messages` exactly.

### Client-to-server frames

The client can push only two upstream messages:

```json
{ "type": "presence_update", "status": "afk" }
{ "type": "typing", "channel_id": "..." }
```

Anything else is dropped server-side. Presence values: `online`,
`idle`, `afk`, `dnd`. (`offline` is system-set on disconnect, not
user-pickable.)

### Heartbeats and disconnect

The server pings every 25 s; the client should reply with a pong.
Missing two consecutive pongs tears the session down — the user
flips to `offline` and a `user_presence` event broadcasts to
their visible channels. Clients should reconnect with exponential
backoff (start at 1 s, cap at 30 s) on any unexpected close.

---

## Internal SFU routes (reference)

These are signed-only routes the media-sfu peer uses to talk back
to the instance. **Clients should not call them.** Listed for
completeness.

| Method | Path | Purpose |
|--------|------|---------|
| POST   | `/api/internal/v1/voice/consume-join-token` | One-time join-token consume from SFU |
| POST   | `/api/internal/v1/voice/events`             | Signed event push from SFU |
| POST   | `/api/internal/v1/voice/bootstrap-config`   | SFU startup handshake |

Signature verification uses the shared SFU secret from the
instance's runtime config. Misconfigured or unauthenticated
calls return 401 / 403.

---

## Where to go next

- **[Server architecture](architecture.md)** — runtime layout,
  boot sequence, manager map, request pipeline.
- **[Roles & privileges](roles.md)** — privilege catalog and how
  to read the `resolved_privileges` field.
- **[Python SDK](sdk.md)** — high-level async wrapper.
- **[Client (web + desktop)](client.md)** — what the official
  Electron client does on top of this surface.
