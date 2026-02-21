# PufferBlow Server Wiki

This wiki documents how the `pufferblow` server works today, with focus on decentralization, federation, and the current runtime architecture.

## 1. Platform Model

PufferBlow is designed as an **instance-first communication platform**:

- Each deployed server instance is an independent community server.
- Users create accounts on one instance.
- Channels and voice channels are local to that instance.
- Cross-instance direct messaging is handled through ActivityPub-based federation.

This keeps local server governance simple (Discord-style server ownership) while still enabling federated communication between instances.

## 2. Current Server Layout

Main server package: `pufferblow/pufferblow/`

```text
pufferblow/
  pufferblow/
    api/
      routes/                 # Modular HTTP routers
      activitypub/            # Federation + DM bridge logic
      auth/                   # JWT + decentralized node auth
      database/               # SQLAlchemy models + handler
      storage/                # Local/S3 backend + SSE AES encryption
      websocket/              # Real-time WS distribution
      webrtc/                 # Voice channel session manager
      ...
    core/
      bootstrap.py            # APIInitializer and manager wiring
    server/
      app.py                  # ASGI export
    cli/
      cli.py                  # Typer CLI
      textual_setup.py        # Textual setup wizard
```

## 3. Boot and Dependency Wiring

`APIInitializer` (in `pufferblow/core/bootstrap.py`) is the central runtime container.  
At startup (`FastAPI` lifespan in `pufferblow/api/api.py`) it loads:

1. Config (`ConfigHandler` + `Config`)
2. Database engine (`Database`) and `DatabaseHandler`
3. Core managers:
   - `AuthTokenManager`
   - `UserManager`
   - `ChannelsManager`
   - `MessagesManager`
   - `WebSocketsManager`
   - `StorageManager` (if storage dependencies are available)
   - `BackgroundTasksManager`
   - `SecurityChecksHandler`
   - `DecentralizedAuthManager`
   - `ActivityPubManager`
4. WebRTC singleton initialization
5. Background scheduled task registrations

## 4. Request Pipeline

For HTTP requests, flow is:

1. CORS middleware
2. `SecurityMiddleware` (query/form security checks on privileged routes)
3. `RateLimitingMiddleware` (sliding-window with bucketed endpoint limits)
4. Request logging middleware (request id + duration)
5. Route handler

Most modular routes are registered through `pufferblow/api/routes/register.py`.

## 5. Authentication Model

### 5.1 User Sessions (JWT + Refresh)

On signup/signin:

- Access JWT and refresh token are issued by `AuthTokenManager`.
- Access token includes:
  - `sub` (user id)
  - `origin_server`
  - `iss` (instance id)
  - `iat`, `exp`, `jti`
- Refresh token is stored as hash in database.

Refresh flow:

- `POST /api/v1/auth/refresh` validates refresh token, rotates it, and returns a new token pair.
- `POST /api/v1/auth/revoke` revokes a refresh token.

### 5.2 Instance-Locked Logins

Account locality is enforced in two places:

- `users.origin_server` stores where account was created.
- Sign-in checks current instance (`API_HOST:API_PORT`) matches `origin_server`.
- JWT decode validates `origin_server` claim against current instance.

Result: users cannot sign in to other instances using local credentials from a different origin instance.

## 6. Decentralized Node Auth

Separate from user JWT auth, decentralized node sessions support node-to-node delegated access:

- `POST /api/v1/auth/decentralized/challenge`
- `POST /api/v1/auth/decentralized/verify`
- `POST /api/v1/auth/decentralized/introspect`
- `POST /api/v1/auth/decentralized/revoke`

Flow:

1. User requests challenge bound to `node_id`.
2. Node verifies challenge via signature/shared secret.
3. Server issues hashed session token with scope + expiration.
4. Session can be introspected and revoked.

Tables:

- `decentralized_auth_challenges`
- `decentralized_node_sessions`

## 7. Decentralization and Federation (ActivityPub)

### 7.1 Identity Mapping

Each local user can have an ActivityPub actor:

- Actor URI: `/ap/users/{user_id}`
- Inbox: `/ap/users/{user_id}/inbox`
- Outbox: `/ap/users/{user_id}/outbox`
- Shared inbox: `/ap/inbox`

WebFinger endpoint:

- `GET /.well-known/webfinger`

### 7.2 Local vs Remote Users

Remote actors are cached in `activitypub_actors`.  
If a remote sender needs to appear in local DM history, a local **shadow user** is created and linked to the actor.

### 7.3 DM Federation Model

Cross-instance DM uses ActivityPub `Create` with `Note` objects:

- Local message persisted first.
- For remote peers, message is delivered to remote inbox/shared inbox.
- Incoming remote notes are processed from inbox and delivered into local conversation history.
- Local recipients receive WebSocket push updates.

### 7.4 Follow Handshake

Implemented follow flow:

- Send `Follow` activity to remote actor.
- Persist follow relation.
- Process incoming `Accept` and mark follow accepted.

Tables:

- `activitypub_actors`
- `activitypub_follows`
- `activitypub_inbox_activities`
- `activitypub_outbox_activities`

## 8. Messaging Model

### 8.1 Channels

Channels are instance-local and support:

- `text`
- `voice`
- `mixed`

Private channels have membership checks and route-level authorization.

### 8.2 Direct Messages

DMs are modeled as conversations by `conversation_id`.  
For federated DMs, conversation id is deterministically derived from actor URIs so both sides resolve the same logical thread.

## 9. Real-Time Stack

### 9.1 WebSockets

Endpoints:

- `ws://<host>/ws` (global multi-channel stream)
- `ws://<host>/ws/channels/{channel_id}` (channel-scoped stream)

`WebSocketsManager` maintains active connections and supports:

- broadcast by channel
- targeted broadcast by user
- permission-aware dispatch

### 9.2 WebRTC Voice

Voice channels are managed by `WebRTCManager` (`aiortc`-based):

- Join: `POST /api/v1/channels/{channel_id}/join-audio`
- Leave: `POST /api/v1/channels/{channel_id}/leave-audio`
- Status: `GET /api/v1/channels/{channel_id}/audio-status`

The manager tracks channel participants and runs cleanup for stale connections.

## 10. Storage, CDN, and SSE Encryption

`StorageManager` supports local/S3 backends and server-side encryption (SSE):

- Envelope format uses magic prefix `PBSE1`
- AES-256-GCM for content encryption/decryption
- Key sourced from config/env and normalized to 32 bytes

Storage APIs live under `/api/v1/storage/*` with compatibility file serving routes (`/api/v1/cdn/file/...`, `/api/v1/storage/file/...`, `/storage/{file_hash}`).

Related tables:

- `file_objects`
- `file_references`

## 11. Security Controls

- Sliding-window rate limiting with endpoint buckets (`auth`, `uploads`, `messages`, `default`)
- Progressive warnings and cooldowns
- Automatic persistent IP block for abusive clients
- Route-level authz helpers (`get_current_user`, `require_admin`, `require_server_owner`)
- Security checks handler validates token format, channel IDs, usernames, and other sensitive params

## 12. Database Design (Current)

Core entities:

- `users`, `channels`, `messages`
- `message_read_history`
- `server`, `server_settings`
- `auth_tokens` (refresh/legacy token storage support)
- moderation/activity tables (`blocked_ips`, `activity_audit`, `activity_metrics`, `chart_data`)
- federation tables (`decentralized_*`, `activitypub_*`)
- storage tables (`file_objects`, `file_references`)

`DatabaseHandler` creates tables idempotently and inserts default server settings for PostgreSQL.

## 13. Background Tasks

Registered periodic jobs include:

- storage cleanup
- auth token cleanup
- server stats update
- chart data update
- release check
- activity metrics update

These are wired during startup through the background task manager lifespan hook.

## 14. CLI and Setup Flow

CLI entrypoint: `pufferblow.cli.cli:run`

Primary commands:

- `pufferblow setup` (supports Textual TUI wizard)
- `pufferblow serve`
- `pufferblow storage setup|test|migrate`

The setup flow provisions DB connectivity, server metadata, and initial owner account.

## 15. Important Current Boundaries

1. Federation currently focuses on **cross-instance identity + DMs + follows**.
2. Channels and server administration remain local to each instance.
3. The API surface is routed through modular handlers under `pufferblow/api/routes/`.

## 16. How to Extend Safely

When adding new features:

1. Add logic in manager classes first.
2. Expose via route modules in `api/routes/`.
3. Keep auth checks in `dependencies.py`.
4. Persist with explicit table/model additions under `api/database/tables/`.
5. Document new contracts in both:
   - this `WIKI.md`
   - Sphinx docs under `docs/`
