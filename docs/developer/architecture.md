# Server architecture

This page documents how the Pufferblow server is wired at runtime,
how requests move through it, and the data + federation model that
underpins it. It's the canonical merge of three earlier docs
(`WIKI.md`, `docs/server_wiki.rst`, `docs/decentralization.rst`).
If you find a conflict between this page and one of those, this
page wins.

!!! note "Audience"
    This is the developer-facing architecture overview. If you
    want to **run** an instance, start with the
    [operator section](../operator/index.md) instead.

## Platform model

Pufferblow is **instance-first**: each running server is an
independent community. Accounts, channels, and voice channels are
local to the instance you signed up on. Cross-instance direct
messages and follows are layered on via ActivityPub.

That keeps governance simple — Discord-style server ownership —
without locking communities into one platform.

### What the data plane actually is

- **Server** — plain Python + FastAPI.
- **Database** — PostgreSQL via SQLAlchemy (SQLite in tests).
- **Cache** — memcached.
- **Object storage** — local filesystem or any S3-compatible API
  (MinIO, R2, S3).

There is **no Supabase, Firebase, or other BaaS**. Earlier
revisions of the get-started doc shipped Supabase screenshots and
misled people; that's gone now. The setup flow is:

1. Install PostgreSQL (or point at an existing one).
2. `pufferblow setup` provisions the DB and writes
   `~/.pufferblow/config.toml`.
3. `pufferblow serve` boots the API.

For production, the supported path is the Docker Compose stack —
see [operator/docker.md](../operator/docker.md).

## Repository layout

```text
pufferblow/
  pufferblow/
    api/
      routes/                 # Modular HTTP routers
      activitypub/            # Federation + DM bridge
      auth/                   # JWT + decentralized-node auth
      database/               # SQLAlchemy models + handler
      storage/                # Local/S3 backend + AES-GCM SSE
      websocket/              # Real-time WS distribution
      voice/                  # SFU control plane + session manager
    core/
      bootstrap.py            # APIInitializer + manager wiring
    server/
      app.py                  # ASGI export
    cli/
      cli.py                  # Typer CLI
      textual_setup.py        # Textual setup wizard
```

## Boot sequence

`APIInitializer` (`pufferblow/core/bootstrap.py`) is the central
runtime container. FastAPI's lifespan calls it during startup. It
loads, in order:

1. Config (`ConfigHandler` + `Config`).
2. Database engine (`Database`) and `DatabaseHandler`.
3. Core managers — `AuthTokenManager`, `UserManager`,
   `ChannelsManager`, `MessagesManager`, `WebSocketsManager`,
   `StorageManager` (if storage deps are present),
   `BackgroundTasksManager`, `SecurityChecksHandler`,
   `DecentralizedAuthManager`, `ActivityPubManager`.
4. Voice session manager.
5. Background scheduled tasks.

The ASGI export lives at `pufferblow/server/app.py` and points at
`pufferblow.api.api:api`.

## Manager map

| Manager | Responsibility |
| --- | --- |
| `AuthTokenManager` | JWT access tokens, refresh-token lifecycle, origin-instance checks |
| `UserManager` | Signup, signin, profile updates, account locality |
| `ChannelsManager` | Channel CRUD, membership checks, voice-channel integration |
| `MessagesManager` | Channel + DM message persistence and reads |
| `StorageManager` | Local / S3 storage abstraction, validation, server-side encryption |
| `DecentralizedAuthManager` | Node-level challenge / verify / introspect / revoke |
| `ActivityPubManager` | WebFinger, inbox / outbox processing, cross-instance DMs |
| `WebSocketsManager` | Real-time fanout by channel or user |
| `VoiceSessionManager` | Issues SFU join tokens, tracks voice sessions, processes `media-sfu` callbacks |

## HTTP request pipeline

Every request goes through, in order:

1. **CORS middleware** — origins are explicitly allowlisted in
   `config.toml`.
2. **`SecurityMiddleware`** — query / form validation on
   privileged routes.
3. **`RateLimitingMiddleware`** — sliding-window per-IP limits,
   bucketed by endpoint kind (`auth`, `uploads`, `messages`,
   `default`), with progressive warnings, cooldowns, and
   automatic block-listing for abusive clients.
4. **Request logging** — request id + duration.
5. **Route handler.**

Feature routes are mounted from `pufferblow/api/routes/` via
`register.py`.

## Authentication

### User sessions

Access JWTs and refresh tokens are issued by `AuthTokenManager`.
The access token claims:

- `sub` — user id
- `origin_server` — the instance this account lives on
- `iss` — instance id
- `iat`, `exp`, `jti`

Refresh tokens are stored as a **hash** in the database. The
refresh flow rotates the refresh token on every use:

- `POST /api/v1/auth/refresh` — validates, rotates, returns a new
  token pair.
- `POST /api/v1/auth/revoke` — invalidates a refresh token.

### Instance-locked logins

Account locality is enforced in two places:

- `users.origin_server` records where the account was created.
- Sign-in checks that the current instance (`API_HOST:API_PORT`)
  matches the user's `origin_server`.
- JWT decode validates the `origin_server` claim against the
  current instance identity.

Net effect: a user's credentials only work on the instance they
signed up on. Federation moves *messages*, not *logins*.

### Decentralized node auth

Separate from user JWTs, the server exposes a node-to-node auth
channel for delegated access:

```
POST /api/v1/auth/decentralized/challenge
POST /api/v1/auth/decentralized/verify
POST /api/v1/auth/decentralized/introspect
POST /api/v1/auth/decentralized/revoke
```

Flow:

1. A node requests a challenge bound to its `node_id`.
2. The node verifies the challenge (signature / shared secret).
3. The server issues a hashed session token with a scope +
   expiration.
4. The session can be introspected or revoked later.

State lives in `decentralized_auth_challenges` and
`decentralized_node_sessions`.

## Federation (ActivityPub)

### Identity surface

Each local user can have an ActivityPub actor:

- Actor URI — `/ap/users/{user_id}`
- Inbox — `/ap/users/{user_id}/inbox`
- Outbox — `/ap/users/{user_id}/outbox`
- Shared inbox — `/ap/inbox`
- WebFinger — `GET /.well-known/webfinger`

### Local vs remote users

Remote actors are cached in `activitypub_actors`. When a remote
sender needs to appear in local DM history, the server creates a
**shadow user** linked to the remote actor so the conversation
view is consistent on both sides.

### DM federation

Cross-instance DMs use ActivityPub `Create` activities wrapping
`Note` objects.

1. The message is persisted locally first.
2. If the peer is local, it's delivered via WebSocket fanout.
3. If the peer is remote, the server emits a `Create(Note)` to
   the remote inbox (or shared inbox).
4. Incoming remote `Create(Note)` activities are persisted and
   pushed to local recipients in real time.

Conversation ids are deterministically derived from the actor
URIs on both ends, so both sides resolve the same logical thread.

### Follow handshake

- Send `Follow` to the remote actor.
- Persist the follow relation.
- Process incoming `Accept` and mark the follow accepted.

Tables: `activitypub_actors`, `activitypub_follows`,
`activitypub_inbox_activities`, `activitypub_outbox_activities`.

## Messaging model

### Channels

Channels are **instance-local** and come in three flavors:

- `text`
- `voice`
- `mixed`

Private channels enforce membership checks at the route layer.

### Direct messages

DMs are modeled as conversations keyed by `conversation_id`. For
federated DMs the id is derived from both actors so the same
logical thread shows up on both instances.

## Real-time and voice

### WebSockets

- Global stream — `ws://<host>/ws` (all channels for the user).
- Channel stream — `ws://<host>/ws/channels/{channel_id}`.

`WebSocketsManager` handles:

- broadcast by channel
- targeted broadcast by user
- permission-aware dispatch (private-channel members only see
  what they're allowed to see)

### Voice via `media-sfu`

Voice is a split architecture:

- **Control plane** — the Python server. Owns authz, join-token
  issuance, session state, and the internal callback handler.
- **Media plane** — `media-sfu` (Go + Pion). Owns
  `GET /rtc/v1/ws?join_token=<token>`, RTP forwarding, and
  participant lifecycle.

Public voice APIs live under `/api/v2/voice/*`. Instance health
mirrors SFU state into:

- `GET /healthz`
- `GET /readyz`
- `GET /api/v1/system/instance-health`

## Storage and encryption

`StorageManager` supports local + S3 backends with optional
server-side encryption (SSE).

- Envelope format — magic prefix `PBSE1`.
- Cipher — AES-256-GCM.
- Key — sourced from config or env and normalized to 32 bytes.

This is **server-at-rest** encryption: the server has the key.
End-to-end encryption is on the roadmap, not in v1.0 — see
[release notes](../operator/release-notes-v1.0.md).

Storage APIs live under `/api/v1/storage/*`. Canonical file URLs
are served from `/storage/{file_hash}`. Metadata tables:
`file_objects`, `file_references`.

## Database design (current)

Core entities — `users`, `channels`, `messages`,
`message_read_history`, `server`, `server_settings`,
`auth_tokens`.

Moderation + metrics — `blocked_ips`, `activity_audit`,
`activity_metrics`, `chart_data`.

Federation — `decentralized_*`, `activitypub_*`.

Storage — `file_objects`, `file_references`.

`DatabaseHandler` creates tables idempotently and seeds default
server settings on PostgreSQL.

## Background tasks

Registered during startup:

- storage cleanup
- auth-token cleanup
- server-stats update
- chart-data update
- release check
- activity-metrics update

## CLI

Entrypoint — `pufferblow.cli.cli:run`.

Primary commands:

- `pufferblow setup` (includes a Textual TUI wizard)
- `pufferblow serve`
- `pufferblow storage setup|test|migrate`

Recent perf work: command modules import lazily; heavyweight
bootstrap / config / storage imports are deferred until first
use; `scripts/benchmark_cli_startup.py` measures startup for
`--help`, `version`, `serve --help`, and `storage --help`.

## Current boundaries

1. **Federation is scoped** to cross-instance identity, follows,
   and DMs. Channels and admin remain local.
2. **Voice is SFU-only.** The older mesh path is gone.
3. **API surface** is routed through modular handlers under
   `pufferblow/api/routes/`.

## Extending the server safely

When you add a feature:

1. Implement the logic in a **manager class** first.
2. Expose it via a route module under `api/routes/`.
3. Put auth checks in `dependencies.py`, not the route body.
4. Persist with explicit table / model additions under
   `api/database/tables/`.
5. Document the new contract here.
