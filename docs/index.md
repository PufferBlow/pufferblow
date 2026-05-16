# Pufferblow documentation

Pufferblow is a self-hosted, open-source community server with
encrypted messaging at rest, ActivityPub federation, voice
channels, and a role-based privilege system.

This site is organized by **who you are**:

[Operator :octicons-arrow-right-24:](operator/index.md){ .md-button }
You're running an instance. Start here.

<!-- Future sections — added in later commits:

[User :octicons-arrow-right-24:](user/index.md){ .md-button }
You want to join a community.

[Developer :octicons-arrow-right-24:](developer/index.md){ .md-button }
You're building against the API or hacking on the server.

-->

## Where things live

- **Operator docs** (this section) — installing and running a
  Pufferblow instance: Docker, backups, federation, CLI, the
  v1.0 release notes.
- The repo's [`README.md`](https://github.com/PufferBlow/pufferblow/blob/main/README.md)
  is the entrypoint for evaluation and first-time install.
- API reference is served live at `/docs` on any running
  instance (FastAPI's built-in Swagger UI).
- [`SECURITY.md`](https://github.com/PufferBlow/pufferblow/blob/main/SECURITY.md)
  covers vulnerability disclosure.
- [`CONTRIBUTING.md`](https://github.com/PufferBlow/pufferblow/blob/main/CONTRIBUTING.md)
  is for code contributions.

## Status

Pufferblow is in `0.x` beta. Read
[the v1.0 release notes](operator/release-notes-v1.0.md) before
deploying — they spell out what ships in v1.0 and what's deferred.
