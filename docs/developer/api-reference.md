# API reference

The Pufferblow API is documented automatically from the FastAPI
app's OpenAPI schema. The hand-written reference that used to
live in `docs/api_reference.rst` (736 lines) was being kept in
sync by typing, which means it drifted — when a route's prefix
changed from `/api/v1/voice` to `/api/v2/voice`, the hand-written
doc didn't notice. This page is generated from the same code
that handles requests, so it can't lie.

## How to use it

**Live, from a running instance** — every Pufferblow server
serves Swagger UI at:

```
http://<your-instance>:7575/docs
```

and the raw JSON schema at:

```
http://<your-instance>:7575/openapi.json
```

This is the most up-to-date view of any specific server because
it reflects exactly the code that server is running.

**Embedded here** — this page renders the OpenAPI schema
exported at docs-build time, which is whatever shipped with the
last commit on `main`.

!!swagger ./openapi.json!!

## Regenerating the embedded schema

The schema file at `docs/developer/openapi.json` is produced by:

```bash
poetry run python scripts/export_openapi.py
```

This imports the FastAPI app and calls `app.openapi()` — no
database connection required, but it does need every import-
time dependency installed (run it inside the poetry env).

CI runs this on every push to `main` so the deployed docs
always match the code. Locally, run it whenever you've changed
a route signature and want to preview the rendered docs.

For pretty-printed JSON (useful when reviewing diffs):

```bash
poetry run python scripts/export_openapi.py --pretty
```

## What's documented

The schema covers every public HTTP route mounted under
`pufferblow.api.routes`:

- **Auth** — signup, signin, refresh, revoke, decentralized
  node auth.
- **Users** — profile, status, role assignment.
- **Channels** — text, voice, mixed; CRUD + membership.
- **Messages** — channel messages and DMs.
- **Storage** — uploads, downloads, file metadata. Canonical
  URLs are at `/storage/{file_hash}`.
- **System** — server info, instance health, role + privilege
  catalog.
- **Federation** — ActivityPub actor / inbox / outbox endpoints
  plus `/.well-known/webfinger`.
- **Voice** — `/api/v2/voice/*` (the v1 path is no longer
  served).

WebSocket endpoints (`/ws`, `/ws/channels/{channel_id}`) are
not part of the OpenAPI surface — FastAPI doesn't include them.
The protocol is documented in the
[Server architecture](architecture.md#websockets) page.

## Stability

The API is currently `0.x` beta. Breaking changes can land
before v1.0; the schema is the source of truth for what's
present today, not a contract. The `1.0` tag will introduce a
real compatibility window.
