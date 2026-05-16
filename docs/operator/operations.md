# Pufferblow — Administrator Guide

Day-to-day operations for someone running a Pufferblow instance. Covers the
CLI tool, runtime config, secret rotation, the IP blocklist, audit logs, and
the storage backend. For first-time setup see
[DOCKER_PRODUCTION.md](DOCKER_PRODUCTION.md); for what v1.0 actually
ships see [V1_0_CAVEATS.md](V1_0_CAVEATS.md).

---

## CLI quick reference

The `pufferblow` command is the operator entry point. It lives inside the
`pufferblow-server` container — shell in with
`docker compose exec pufferblow-server bash` if you're running the
Compose stack.

| Command                                | What it does                                                              |
| -------------------------------------- | ------------------------------------------------------------------------- |
| `pufferblow version`                   | Print the installed version.                                              |
| `pufferblow setup`                     | Interactive first-time setup (server metadata, secrets, SFU bootstrap).   |
| `pufferblow setup --setup-server`      | Only (re)create the initial server row (name, description, welcome).      |
| `pufferblow setup --update-server`     | Update an existing server's name/description/welcome.                     |
| `pufferblow setup --setup-media-sfu`   | Write a fresh `[media-sfu]` section to `config.toml` (rotates the secret).|
| `pufferblow setup --backup`            | Dump server metadata to a timestamped JSON before any setup change.       |
| `pufferblow serve`                     | Run the API. Same entry point the container uses.                         |
| `pufferblow serve --log-level 1`       | Verbose (DEBUG). `--log-level 0=INFO 1=DEBUG 2=ERROR 3=CRITICAL`.         |
| `pufferblow serve --debug`             | Include tracebacks in error responses. Don't enable in production.        |
| `pufferblow serve --dev`               | Uvicorn auto-reload. Local development only.                              |
| `pufferblow storage setup`             | Interactive wizard for the storage backend (local FS vs S3).              |
| `pufferblow storage test`              | Round-trip a small upload against the configured backend.                 |
| `pufferblow storage migrate ...`       | Move file objects between backends. See `--help` for flags.               |

---

## Configuration files

| Path                         | Purpose                                                  |
| ---------------------------- | -------------------------------------------------------- |
| `~/.pufferblow/config.toml`  | The runtime config the server reads on every boot.       |
| `.env` (Compose deploy)      | Compose-level env: DB URI, SFU bootstrap secret, TURN.   |

Anything operationally interesting (DB URI, JWT secret, RTC join secret,
TURN credentials) lives in `config.toml`. The container mounts the
`pufferblow_data` volume at `/root/.pufferblow` so the file persists.

> **Insecure defaults are fatal.** The startup check refuses to run if
> `JWT_SECRET`, `RTC_JOIN_SECRET`, `RTC_INTERNAL_SECRET`, or
> `RTC_BOOTSTRAP_SECRET` are still the `change-this-*` placeholders.
> Regenerate them with `openssl rand -hex 32` and write them into
> `config.toml` before booting in production.

---

## Secret rotation

Stop the stack first; the running server caches secrets in memory.

```bash
docker compose -f docker-compose.prod.server.yml down

# Edit config.toml inside the volume:
docker run --rm -it -v pufferblow_data:/data alpine sh -c '\
  apk add nano && nano /data/config.toml'

# Restart:
docker compose -f docker-compose.prod.server.yml up -d
```

| Secret                  | What rotating it invalidates                                        |
| ----------------------- | ------------------------------------------------------------------- |
| `JWT_SECRET`            | Every issued access token. All users get bounced to login.          |
| `RTC_JOIN_SECRET`       | In-flight voice join tokens. Users in calls disconnect; re-joins OK.|
| `RTC_INTERNAL_SECRET`   | The SFU's HMAC for callbacks. Rotate on both sides together.        |
| `RTC_BOOTSTRAP_SECRET`  | The SFU's config fetch. Rerun `pufferblow setup --setup-media-sfu`. |
| TURN long-term password | Existing TURN allocations. Voice mid-call drops briefly.            |

There is no per-actor RSA key rotation today (federation). That's a v1.1
hardening item — see [V1_0_CAVEATS.md](V1_0_CAVEATS.md).

---

## Server metadata (name / description / welcome message)

```bash
docker compose exec pufferblow-server pufferblow setup --update-server
```

This walks you through changing the user-visible fields without touching
secrets. Safe to run on a live instance.

---

## Storage backend

Pufferblow ships with two backends: a local filesystem (default) and an
S3-compatible API (MinIO, R2, AWS S3).

```bash
# Interactive picker:
docker compose exec pufferblow-server pufferblow storage setup

# Round-trip test the configured backend:
docker compose exec pufferblow-server pufferblow storage test

# Move existing files local → s3 in 50-object batches, dry run first:
docker compose exec pufferblow-server pufferblow storage migrate \
  --source-provider local --target-provider s3 \
  --batch-size 50 --dry-run

# Real run (no --dry-run):
docker compose exec pufferblow-server pufferblow storage migrate \
  --source-provider local --target-provider s3 --batch-size 50
```

Migration is non-destructive on success: source files are kept until you
explicitly remove them. Failed objects stay on the source so a re-run
picks them up.

S3 paths are SSE-encrypted at rest (server-side). The decryption key
material lives in `config.toml`, NOT in S3 — losing the toml means the
on-disk ciphertext is unrecoverable. Back it up (see
[BACKUP.md](BACKUP.md)).

---

## Audit log + activity metrics

`activity_audit` rows record privileged operations (role changes, channel
deletes, moderation actions). `activity_metrics` rows record aggregate
counts (messages, sign-ups, voice minutes) for the admin dashboard.

Both tables live in Postgres and grow over time. There's no automatic
trimming — operators on a long-running instance should periodically
either truncate (lose history) or archive to cold storage:

```sql
-- Archive everything older than 90 days into a sibling table:
CREATE TABLE activity_audit_archive (LIKE activity_audit);
INSERT INTO activity_audit_archive
  SELECT * FROM activity_audit WHERE created_at < NOW() - INTERVAL '90 days';
DELETE FROM activity_audit WHERE created_at < NOW() - INTERVAL '90 days';
```

In-app view: the Admin Control Panel → "Logs" tab. v1.0 ships a thin
viewer; serious forensic work still happens directly in the DB.

---

## IP blocklist + abuse handling

The `blocked_ips` table is populated two ways:

1. **Automatic** — the rate-limit middleware promotes a repeatedly-warned
   IP from "in cooldown" to "blocked." Watch for
   `blocked_ip_promoted` in the API logs.
2. **Manual** — Admin Control Panel → "Blocked IPs" tab → "Block IP."

Manual unblock from the same tab, or directly:

```sql
DELETE FROM blocked_ips WHERE ip_address = '1.2.3.4';
```

If you run behind a reverse proxy and rate-limit hits are firing on
`127.0.0.1`, set `TRUSTED_PROXIES` in `config.toml` so
`X-Forwarded-For` is honored only when the connecting IP matches.

---

## Healthchecks for monitoring

Both endpoints return JSON and are safe to hit unauthenticated.

| Endpoint    | Status                                                            |
| ----------- | ----------------------------------------------------------------- |
| `/healthz`  | API process is up. Liveness probe.                                |
| `/readyz`   | DB connected, managers wired, runtime config loaded. Readiness.   |

Compose uses `/readyz` so the SFU's `depends_on` waits for a real
bootstrap.

External monitoring (Uptime Kuma, statping, etc.) should hit `/healthz`
on a 30-second interval. Alert on three consecutive failures, not one —
brief restarts during deploys are normal.
