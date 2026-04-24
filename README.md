<div align="center">

<img src="https://raw.githubusercontent.com/PufferBlow/client/main/public/pufferblow-logo.svg" width="120" alt="Pufferblow logo" />

# Pufferblow

**A self-hosted, open-source community platform built for privacy and control.**

[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-blue?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![CI](https://img.shields.io/github/actions/workflow/status/PufferBlow/pufferblow/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/PufferBlow/pufferblow/actions)
[![GitHub Stars](https://img.shields.io/github/stars/PufferBlow/pufferblow?style=flat-square&color=yellow)](https://github.com/PufferBlow/pufferblow/stargazers)
[![GitHub Issues](https://img.shields.io/github/issues/PufferBlow/pufferblow?style=flat-square)](https://github.com/PufferBlow/pufferblow/issues)
[![Version](https://img.shields.io/badge/version-0.0.1--beta-orange?style=flat-square)](https://github.com/PufferBlow/pufferblow/releases)

> **Note:** The project is currently in beta. Breaking changes may occur before v1.0.

</div>

---

## What is Pufferblow?

Pufferblow is a self-hosted platform for building online communities — think of it as a privacy-respecting, open-source alternative to Discord or Guilded that you fully own and operate.

You host the server on your own machine or VPS. You control the data, the rules, and the people. No third-party company can read your messages, sell your data, or shut down your community.

Key properties:

- **Self-hosted** — runs on any Linux machine or VPS; no cloud dependency
- **End-to-end secure** — messages are encrypted with Blowfish; passwords hashed with bcrypt
- **Federated** — instances can connect to each other via ActivityPub, so communities on separate servers can interact
- **Role-based** — a fine-grained privilege system lets you delegate moderation, file management, channel control, and more
- **Voice-capable** — integrated WebRTC voice channels through the companion `media-sfu` service
- **Extensible** — a REST API and official Python SDK (`pypufferblow`) let you build bots and integrations

---

## Project Layout

Pufferblow is made up of four repositories that work together:

| Repository | Language | Role |
|---|---|---|
| **[pufferblow](https://github.com/PufferBlow/pufferblow)** | Python / FastAPI | Control plane — REST API, auth, storage, federation |
| **[client](https://github.com/PufferBlow/client)** | TypeScript / React / Electron | Desktop and web client |
| **[media-sfu](https://github.com/PufferBlow/media-sfu)** | Go / Pion WebRTC | Media plane — WebRTC voice forwarding |
| **[pypufferblow](https://github.com/PufferBlow/pypufferblow)** | Python | Official SDK and bot framework |

---

## Requirements

- Python 3.10 or later
- PostgreSQL 14 or later
- A Linux or macOS host (Windows via WSL is supported for development)

Optional but recommended for voice channels:

- A running [media-sfu](https://github.com/PufferBlow/media-sfu) instance
- A TURN server (e.g. coturn) for clients behind strict NAT

---

## Installation

### 1. Install via pip

```bash
pip install pufferblow
```

Or install from source:

```bash
git clone https://github.com/PufferBlow/pufferblow.git
cd pufferblow
pip install .
```

### 2. First-time setup

Run the interactive setup wizard. It creates `~/.pufferblow/config.toml` and initialises the database:

```bash
pufferblow setup
```

The wizard will ask for:

- PostgreSQL connection details
- An admin account (username + password)
- Server name and description

### 3. Start the server

```bash
pufferblow serve
```

The API will be available at `http://0.0.0.0:7575` by default.

---

## Configuration

All runtime settings live in `~/.pufferblow/config.toml`. The file is created by `pufferblow setup` and documented inline.

Key sections:

```toml
[server]
host    = "0.0.0.0"
port    = 7575
workers = 4

[database]
host     = "localhost"
port     = 5432
username = "pufferblow"
password = "change-me"
database = "pufferblow"

[security]
cors_origins           = ["http://localhost:5173"]
cors_allow_credentials = true

[media-sfu]
bootstrap_secret    = "change-this"
bootstrap_config_url = "http://localhost:7575/api/internal/v1/voice/bootstrap-config"
bind_addr           = ":8787"
```

After any change, restart the server to apply it.

---

## CLI Reference

```
pufferblow setup              First-time setup wizard
pufferblow serve              Start the API server
pufferblow setup --update-server   Update server name/description
pufferblow setup --setup-media-sfu Configure the media-sfu integration
pufferblow version            Print the installed version
```

---

## API Overview

The REST API is available at `/api/v1/`. Interactive documentation (Swagger UI) is served at `/docs` when the server is running.

### Health

| Endpoint | Description |
|---|---|
| `GET /healthz` | Control-plane health |
| `GET /readyz` | Readiness check |
| `GET /api/v1/system/instance-health` | Full health including media-sfu |

### Core Resources

| Resource | Prefix |
|---|---|
| Users | `/api/v1/users` |
| Channels | `/api/v1/channels` |
| Messages | `/api/v1/messages` |
| Storage | `/api/v1/storage` |
| Roles & Privileges | `/api/v1/system` |
| Federation | `/api/v1/federation` |
| Voice | `/api/v1/voice` |
| Direct Messages | `/api/v1/dms` |

---

## Architecture

```
                    ┌────────────────────────────────┐
                    │        Pufferblow API           │
                    │   (FastAPI · Python control     │
                    │    plane, port 7575)            │
                    └──────────┬─────────────────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
     ┌────────▼──────┐  ┌──────▼──────┐  ┌─────▼──────────┐
     │  PostgreSQL    │  │  media-sfu  │  │  File Storage   │
     │  (state +      │  │  (Go WebRTC │  │  (local or S3)  │
     │   messages)    │  │   SFU :8787)│  │                 │
     └───────────────┘  └─────────────┘  └─────────────────┘
```

---

## Security Model

- **Passwords** are hashed with bcrypt before storage. Plain-text passwords are never persisted.
- **Messages** are encrypted with Blowfish (configurable key derivation rounds) before they are written to the database.
- **Auth tokens** are JWT-based with configurable access (15 min default) and refresh (30 day default) lifetimes.
- **Rate limiting** is applied per IP before requests reach route handlers.
- **CORS** origins are explicitly allowlisted in `config.toml`.
- **Internal API** calls between Pufferblow and media-sfu are signed with HMAC-SHA256.

---

## Role & Privilege System

Every instance ships with four built-in roles: `owner`, `admin`, `moderator`, and `user`. Custom roles can be created from a catalogue of granular privileges:

`create_channels` · `delete_channels` · `edit_channels` · `manage_channel_users` · `view_private_channels` · `send_messages` · `delete_messages` · `edit_messages` · `ban_users` · `mute_users` · `moderate_content` · `view_audit_logs` · `manage_storage` · `upload_files` · `delete_files` · `view_files` · `manage_server_settings` · `manage_server_privileges` · `view_server_stats` · `manage_background_tasks` · `manage_blocked_ips` · `view_users` · `edit_users` · `reset_user_tokens`

---

## Federation

Pufferblow implements a subset of ActivityPub so instances can talk to each other:

- Follow remote users (`user@other-instance.org`)
- Send and receive cross-instance direct messages
- Resolve remote actor profiles via WebFinger

Relevant endpoints: `/.well-known/webfinger`, `/ap/users/{id}`, `/api/v1/federation/*`

---

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=PufferBlow/pufferblow,PufferBlow/client,PufferBlow/media-sfu,PufferBlow/pypufferblow&type=Date)](https://star-history.com/#PufferBlow/pufferblow&PufferBlow/client&PufferBlow/media-sfu&PufferBlow/pypufferblow&Date)

---

## Contributing

Contributions are welcome. Please open an issue before starting work on a non-trivial change so we can discuss approach.

1. Fork the repository
2. Create a branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m "feat: describe the change"`
4. Open a pull request against `main`

---

## Contributors

<!-- ALL-CONTRIBUTORS-BADGE:START -->
[![All Contributors](https://img.shields.io/badge/all_contributors-1-orange.svg?style=flat-square)](#contributors-)
<!-- ALL-CONTRIBUTORS-BADGE:END -->

<!-- ALL-CONTRIBUTORS-LIST:START -->
<table>
  <tbody>
    <tr>
      <td align="center" valign="top" width="14.28%">
        <a href="http://ramsy0dev.github.io">
          <img src="https://avatars.githubusercontent.com/u/86024158?v=4" width="80px;" alt="ramsy0dev" /><br />
          <sub><b>ramsy0dev</b></sub>
        </a><br />
        <a href="https://github.com/PufferBlow/pufferblow/commits?author=ramsy0dev" title="Code">💻</a>
        <a href="#maintenance-ramsy0dev" title="Maintenance">🚧</a>
        <a href="https://github.com/PufferBlow/pufferblow/commits?author=ramsy0dev" title="Documentation">📖</a>
      </td>
    </tr>
  </tbody>
</table>
<!-- ALL-CONTRIBUTORS-LIST:END -->

---

## License

Pufferblow is released under the [GNU General Public License v3.0](LICENSE).
