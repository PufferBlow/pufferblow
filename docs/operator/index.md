# Operator guide

You're running a Pufferblow instance, or about to. This section
is the working operator's manual: install, back up, federate,
operate.

## Start here

1. **[Docker (production)](docker.md)** — the supported deploy
   path. One command brings up the server, Postgres, memcached,
   and (optionally) media-sfu.
2. **[v1.0 release notes](release-notes-v1.0.md)** — read these
   before deploying. They spell out what's real today and what's
   deferred so you don't ship surprises to your users.

## When you need it

- **[Backup & restore](backup.md)** — what to back up, on what
  schedule, and the exact restore procedure on a fresh host.
- **[Federation](federation.md)** — what crosses the wire to
  other instances, expected latency, TURN setup, and how to
  debug stuck deliveries.
- **[Operations & CLI](operations.md)** — secret rotation, audit
  log, blocked IPs, storage management, every flag the CLI
  takes.

## A note on this section

Operator docs were promoted out of root-level `*.md` files in
the repo (`ADMIN.md`, `BACKUP.md`, etc.) into this site so they
have proper navigation, search, and a stable URL. The originals
still exist at the repo root for backwards-compatible links;
this site is the canonical place to read them.
