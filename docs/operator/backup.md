# Pufferblow — Backup & Restore

What to back up, how often, and how to put it all back when a VM dies.
Pufferblow v1.0 stores user-visible state in two places (the Postgres
database and the file storage backend) plus one small but irreplaceable
config file. Lose any of them and the gap is not recoverable from the
others.

---

## What lives where

| Source                              | Contains                                                                  | Replaceable? |
| ----------------------------------- | ------------------------------------------------------------------------- | ------------ |
| Postgres                            | Users, servers, channels, messages, roles, follows, ActivityPub state.    | ❌            |
| File storage (local FS or S3)       | Uploaded images, video, generic files referenced by `file_objects` rows.  | ❌            |
| `~/.pufferblow/config.toml`         | JWT/RTC/S3 secrets, encryption keys, instance ID, federation actor keys.  | ❌            |
| Compose `.env`                      | Postgres password, TURN credentials, optional overrides.                  | ⚠️ rebuildable, but secrets-equivalent — back up like a credential file.|

`config.toml` is the part operators most often forget. The message-at-rest
encryption keys live there. If Postgres is intact but `config.toml` is
gone, every message in the DB becomes unreadable ciphertext.

---

## What ships and what doesn't

- **Scheduler** — `pufferblow setup --backup` writes a `[backup]`
  section into `config.toml` (file dump or mirror mode, hourly cron
  interval). The server's background task manager then runs `pg_dump`
  or `pg_dump | psql` on the schedule you picked. Default is *off* —
  you have to run setup first.
- **On-demand triggers** — `pufferblow backup now` and
  `pufferblow backup mirror` invoke the same code paths immediately,
  useful before a risky change or as part of an external cron that
  pins its own schedule.
- **Not included** — built-in S3 bucket-to-bucket copy, automatic
  off-host upload, anything outside Postgres.

The scheduled backup uses `BACKUP_PATH` (default
`~/.pufferblow/backups`) inside the container's volume. Treat that
directory as on-host: if the host dies, the backups die with it.
You still need off-host copies — `rsync`, `aws s3 sync`, or restic
against `BACKUP_PATH` on whatever cron interval suits your RPO.

---

## Recommended schedule

| Frequency  | What runs                                                                                |
| ---------- | ---------------------------------------------------------------------------------------- |
| Hourly     | `pg_dump` to local disk (kept for 24 h).                                                 |
| Daily      | `pg_dump` to off-host storage (S3 / B2 / remote NFS), kept 30 days.                      |
| Daily      | Snapshot of the `pufferblow_data` volume (config.toml + local storage backend if used). |
| Weekly     | Cold copy of the off-host backup somewhere different — different region or provider.    |

Object-storage upload backends (S3, R2, MinIO with versioning) cover
their own durability — turn on object versioning and lifecycle rules
rather than manually copying files.

---

## Postgres — pg_dump

Two ways to drive the dump, depending on what you want.

**Through the CLI** (uses the config you've already set up — credentials,
path, retention all come from `config.toml`):

```bash
docker compose exec pufferblow-server pufferblow backup now
```

Output lands under `BACKUP_PATH` inside the data volume and the
rotation policy (`BACKUP_MAX_FILES`, default 7) prunes oldest first.

**Directly against Postgres** (the rest of this section). Use this when
you want the dump file written to a path the CLI doesn't know about —
e.g. straight onto a host-mounted off-host volume.

Connect using the same `POSTGRES_USER` / `POSTGRES_PASSWORD` the
container uses (look in your `.env`).

```bash
# One-shot:
docker compose exec -T postgres \
  pg_dump -U pufferblow -d pufferblow --format=custom --compress=9 \
  > pufferblow-$(date +%Y%m%dT%H%M%S).dump

# Same thing as a daily cron entry (host crontab):
0 3 * * * /usr/local/bin/docker compose -f /srv/pufferblow/docker-compose.prod.server.yml \
  exec -T postgres pg_dump -U pufferblow -d pufferblow \
  --format=custom --compress=9 \
  > /srv/backups/pufferblow-$(date +\%Y\%m\%d).dump
```

`--format=custom` is the format `pg_restore` expects. The `--compress=9`
keeps the file ~80% smaller without significant CPU cost.

To validate a dump without restoring it, run a structural check:

```bash
pg_restore --list pufferblow-20260515.dump | head -20
```

A healthy dump lists table CREATE statements; a corrupt dump errors
immediately.

---

## File storage

### Local filesystem backend

Files live under `~/.pufferblow/storage/` (mapped to the
`pufferblow_data` volume). Snapshot the volume or rsync it:

```bash
docker run --rm -v pufferblow_data:/data -v $(pwd):/backup alpine \
  tar -czf /backup/pufferblow-storage-$(date +%Y%m%d).tar.gz -C /data storage
```

### S3 / S3-compatible backend

Don't write your own copier — use the provider's tooling.

- **AWS S3:** turn on Versioning + a 30-day non-current expiration
  lifecycle. Optionally enable Cross-Region Replication.
- **Cloudflare R2 / Backblaze B2 / MinIO:** equivalent versioning
  features. Check your provider's docs.

`config.toml` holds the SSE encryption key. If you copy the bucket but
lose the toml, the copy is useless.

---

## config.toml

It's a single file. Treat it like an SSH private key.

```bash
docker run --rm -v pufferblow_data:/data -v $(pwd):/backup alpine \
  cp /data/config.toml /backup/pufferblow-config-$(date +%Y%m%d).toml

# Restrict permissions on the copy:
chmod 600 pufferblow-config-*.toml
```

Store at least one copy in a different physical location than the host
running Pufferblow. A password manager's secure-notes field works well
for the small-team case.

---

## Restore on a fresh host

```bash
# 1. Bring up Postgres alone first.
docker compose -f docker-compose.prod.server.yml up -d postgres

# 2. Wait for it to be healthy, then restore the dump:
docker compose exec -T postgres pg_restore -U pufferblow -d pufferblow \
  --clean --if-exists < pufferblow-20260515.dump

# 3. Drop the old config.toml back into place BEFORE booting the API.
docker run --rm -v pufferblow_data:/data -v $(pwd):/backup alpine \
  cp /backup/pufferblow-config-20260515.toml /data/config.toml

# 4. Restore local file storage if you used that backend:
docker run --rm -v pufferblow_data:/data -v $(pwd):/backup alpine \
  tar -xzf /backup/pufferblow-storage-20260515.tar.gz -C /data

# 5. Boot the rest of the stack:
docker compose -f docker-compose.prod.server.yml up -d
```

`pg_restore --clean --if-exists` drops existing rows before re-inserting,
so this is safe to run against a partially-populated DB after a botched
half-restore.

---

## Disaster scenarios

| What broke                                  | How to recover                                                              |
| ------------------------------------------- | --------------------------------------------------------------------------- |
| VM destroyed; Postgres dump + config.toml safe | New VM, follow "Restore on a fresh host" above.                          |
| Postgres corrupt; backups intact            | `docker compose down`, restore from dump per above, `docker compose up`.    |
| `config.toml` lost; DB intact               | **Message contents permanently unrecoverable.** Issue new keys via setup; existing rows decrypt to garbage. Start over or accept the loss. |
| S3 bucket deleted; bucket versioning on     | Restore objects from previous versions (provider tooling).                  |
| S3 bucket deleted; no versioning            | Files are gone. Postgres still has the `file_objects` rows pointing at nothing — those rows produce 404s on download. |
| Single user accidentally deleted by admin   | No undo. Restore the most recent dump to a *staging* DB, dump just that user's rows, copy into prod.            |

---

## Federation considerations

Backups capture local-side state only. They don't restore the *trust*
remote instances had in your local actors:

- `activitypub_actors` rows include your RSA private keys. If you change
  them on restore (e.g. by re-running `pufferblow setup` blindly),
  remote instances reject your signed activities until they fetch the
  new actor doc and refresh their cache.
- Inbound deliveries during the outage are buffered on the *remote*
  side — Mastodon retries failed inbox POSTs for ~24h. If your downtime
  is shorter, deliveries resume automatically after the restore.

See [FEDERATION.md](FEDERATION.md) for the operator side of the
federation surface.
