# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

Pufferblow is a self-hosted, open-source community server (think: a
privacy-respecting, self-owned alternative to Discord). This repo is the
**control-plane instance itself** — a full FastAPI application with auth,
storage, federation, and a CLI — not a thin API client or SDK. When talking
about it, call it "the instance" / "the server", not "the API library".

It is one of four sibling repos that work together:

| Repo | Language | Role |
|---|---|---|
| `pufferblow` (this repo) | Python / FastAPI | Control plane — REST API, auth, storage, federation |
| `client` | TypeScript / React / Electron | Desktop and web client |
| `media-sfu` | Go / Pion WebRTC | Media plane — WebRTC voice forwarding |
| `pypufferblow` | Python | Official SDK and bot framework |

**Datastore: plain PostgreSQL via SQLAlchemy (SQLite in tests) + memcached for
caching + local-filesystem-or-S3 object storage. There is no Supabase,
Firebase, or other BaaS involved anywhere in this stack.** `docs/developer/architecture.md`
explicitly calls this out because an earlier revision of the get-started docs
shipped Supabase screenshots by mistake — don't let stray doc images or
screenshots mislead you into assuming Supabase is involved.

## Commands

### Install / run

```bash
poetry install                 # install deps (poetry install --with dev for lint/test tools)
poetry run pufferblow setup    # interactive wizard -> ~/.pufferblow/config.toml, provisions DB
poetry run pufferblow serve    # start the API server (http://0.0.0.0:7575 by default)
poetry run pufferblow serve --dev   # uvicorn auto-reload, development only
```

Dev environment needs a reachable Postgres + memcached; the fastest path is
the Docker Compose stack (`docker-compose.prod.server.yml`, see
`DOCKER_PRODUCTION.md`) — for local dev you only need its `postgres` and
`memcached` services running.

Other CLI subcommands: `pufferblow migrate [--check]`, `pufferblow doctor`,
`pufferblow backup now|mirror`, `pufferblow storage setup|test|migrate`. Full
reference in `ADMIN.md`. Note `migrate` (DB schema) and `storage migrate`
(moving uploaded files between backends) are unrelated commands despite the
shared verb.

### Lint / format (what CI actually runs, per `.github/workflows/lint.yaml`)

```bash
poetry run ruff check .
poetry run black --check .
poetry run isort --check-only .
```

Drop `--check` on black/isort to auto-fix. `.pre-commit-config.yaml` runs the
same tools (plus trailing-whitespace/EOF/yaml/large-file hooks) as git hooks
if you've installed `pre-commit`.

### Tests

```bash
poetry run pytest                                       # full suite
poetry run pytest pufferblow/tests/test_01_signup.py     # one file
poetry run pytest -k "federation"                        # match by name
pytest ./pufferblow/tests/ -x                             # scripts/run_tests.sh — stop on first failure
```

Tests run against a throwaway per-test SQLite DB (see `pufferblow/tests/conftest.py`'s
`client` fixture) — they don't need Postgres. `asyncio_mode = "auto"` is set
in `pyproject.toml`. Test files are numbered (`test_01_signup.py`,
`test_02_signin.py`, ...) reflecting rough dependency/execution order (signup
before signin before profile edits, etc.) rather than being independent;
check `pufferblow/tests/conftest.py` for shared fixtures before adding new
ones.

### Type checking

`basedpyright` is a dev dependency (`tool.basedpyright` in `pyproject.toml`,
`typeCheckingMode = "standard"`); there's no wired-up CI job for it yet but it's
available via `poetry run basedpyright`.

## Architecture

The canonical deep-dive is `docs/developer/architecture.md` — read it before
making non-trivial changes. Summary:

### Boot sequence and the manager-singleton pattern

`APIInitializer` (`pufferblow/core/bootstrap.py`, exported as the singleton
`api_initializer`) is the central runtime container that every route and
manager shares. FastAPI's `lifespan` hook in `pufferblow/api/api.py` calls
`api_initializer.load_objects()` on startup, which in order:

1. Loads config (`ConfigHandler` + `Config`, from `~/.pufferblow/config.toml`).
2. Builds the `Database` engine + `DatabaseHandler`.
3. Constructs the manager graph — `AuthTokenManager`, `UserManager`,
   `ChannelsManager`, `MessagesManager`, `WebSocketsManager`,
   `VoiceSessionManager`, `StorageManager` (optional — degrades gracefully if
   storage deps are missing), `BackgroundTasksManager`,
   `SecurityChecksHandler`, `DecentralizedAuthManager`, `ActivityPubManager`,
   `PingManager` — wiring dependencies between them by hand (e.g.
   `websockets_manager.voice_session_manager` and
   `activitypub_manager.ping_manager` are set after construction to break
   circular deps).
4. Registers periodic background tasks (storage cleanup, auth-token cleanup,
   stats/chart updates, backup, etc.) — skipped unless the process is actually
   serving (`pufferblow serve`), so running CLI commands like `setup` or
   `version` doesn't spin up the scheduler.

`pufferblow/server/app.py` is the ASGI export (`pufferblow.api.api:api`) that
process runners (uvicorn/gunicorn) point at; it re-applies logger config on
import to handle uvicorn's `--reload` subprocess not inheriting the parent's
loguru sinks.

When extending the server: implement logic in a manager class first, expose
it via a route module under `pufferblow/api/routes/` (wired in
`routes/register.py`), put auth checks in `dependencies.py` rather than the
route body, and add new tables under `pufferblow/api/database/tables/`.

### Request pipeline / middleware order

Middleware ordering in `pufferblow/api/api.py` is deliberate and non-obvious:
`SecurityMiddleware` → `RateLimitingMiddleware` → `CORSMiddleware` →
`PrivateNetworkAccessMiddleware`, where the *last* `add_middleware` call ends
up *outermost* in Starlette's stack. PNA has to be outermost because
`CORSMiddleware` short-circuits preflight requests by building the response
itself — PNA needs to sit one layer further out to see and decorate that
already-built response. CORS is disabled entirely (with a warning) if neither
`cors_origins` nor `cors_origin_regex` is set in `config.toml`.

### Platform model

Instance-first: each deployed server is an independent community (accounts,
channels, voice channels are local to the instance). Cross-instance DMs and
follows are layered on via a partial ActivityPub implementation — federation
moves *messages*, not *logins*; a user's credentials only work on the
instance they signed up on (enforced via `users.origin_server` + JWT
`origin_server` claim checks).

### Voice is a split architecture

Python server = control plane only (authz, join-token issuance, session
state, internal callback handling). The actual WebRTC media forwarding lives
in the separate Go `media-sfu` repo. Public voice routes are versioned
differently from the rest of the API (`/api/v2/voice/*` vs `/api/v1/*`
elsewhere) because voice was redesigned after v1 shipped — don't "fix" that
inconsistency without checking `FEDERATION.md`/`V1_0_CAVEATS.md` first.

### Encryption model — server-at-rest, not E2EE

Messages are AES-encrypted before being written to the DB and file storage
uses AES-256-GCM envelope encryption (magic prefix `PBSE1`), but the server
holds the keys in both cases. This is *not* end-to-end encryption — don't
describe it as such in docs or comments. E2EE is roadmap-only; see
`V1_0_CAVEATS.md`.

### Dependency-trimming history (relevant when adding deps)

Recent history in this repo has been actively *removing* dependencies rather
than adding them (see comments in `pyproject.toml`): `typer`→stdlib
`argparse` for the CLI, `textual` setup wizard removed (never wired up),
`sqlalchemy-utils` inlined, `tomli`→stdlib `tomllib`. Prefer stdlib or
already-present libraries over new dependencies unless there's a strong
reason. Note some docs (e.g. `CONTRIBUTING.md`, `docs/developer/architecture.md`'s
CLI section) still reference the old `typer`/Textual CLI and are stale on
this point — trust `pufferblow/cli/cli.py`'s own docstring over them.

## Repo layout

```
pufferblow/
  api/
    routes/        # modular HTTP routers, mounted via routes/register.py
    activitypub/    # federation + DM bridge
    auth/           # JWT + decentralized-node auth
    database/       # SQLAlchemy models + handler + tables/
    storage/        # local/S3 backend + AES-GCM SSE
    websocket/      # real-time WS distribution
    voice/          # SFU control plane + session manager
  core/
    bootstrap.py    # APIInitializer + manager wiring (see Architecture above)
  server/
    app.py          # ASGI export
  cli/
    cli.py          # argparse-based CLI entrypoint
    commands/       # one module per leaf command, imported lazily
  tests/            # numbered pytest files, see Tests above
```

## Other docs worth knowing about

- `V1_0_CAVEATS.md` — what's real in v1.0 (search, voice, federation) vs
  explicitly deferred (E2EE, simulcast, FTS).
- `ADMIN.md` — full CLI/operator reference.
- `DOCKER_PRODUCTION.md` — Compose stack (server, Postgres, memcached,
  optional media-sfu).
- `BACKUP.md` — what to back up and how to restore.
- `FEDERATION.md` — what federates, TURN setup, debugging stuck deliveries.
