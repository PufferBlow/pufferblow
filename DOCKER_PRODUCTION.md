# PufferBlow Server Production Docker

A one-command self-host stack for a Pufferblow server, the SFU sidecar, a
TURN relay, and PostgreSQL.

Files used by this flow:

- `docker-compose.prod.server.yml` — the stack definition
- `Dockerfile` — the image the `pufferblow-server` service builds from
- `.env.server.example` — template for the `.env` you copy and edit

## Services

| Service            | Image / build              | Purpose                                                                |
| ------------------ | -------------------------- | ---------------------------------------------------------------------- |
| `postgres`         | `postgres:16-alpine`       | Primary datastore.                                                     |
| `pufferblow-server`| `./Dockerfile`             | The Python/FastAPI API. Waits for postgres health, exposes `:7575`.    |
| `media-sfu`        | media-sfu repo (Go SFU)    | WebRTC SFU. Waits for `pufferblow-server` health, exposes `:8787`.     |
| `coturn`           | `instrumentisto/coturn`    | TURN relay for clients behind strict NAT. Exposes `:3478` + UDP range. |

## Run

```bash
cp .env.server.example .env
# Edit .env — every `change-me-...` value MUST be replaced.
docker compose --env-file .env -f docker-compose.prod.server.yml up -d --build
```

First boot order (you should see this in `docker compose logs -f`):

1. `postgres` reports healthy.
2. `pufferblow-server` builds, starts, hits `/readyz` once initialized.
3. `media-sfu` builds, starts, fetches its bootstrap config from
   `pufferblow-server`.
4. `coturn` is independent and comes up alongside.

The stack is reachable at:

- API + WS: `http://<host>:7575`
- SFU signaling: `ws://<host>:8787/rtc/v1/ws`
- TURN: `<host>:3478` (TCP and UDP)

## Configuration

### Database

`PUFFERBLOW_DATABASE_URI` is set in the compose file from the
`POSTGRES_*` variables in your `.env`, so a fresh stack works without
any host-side `pufferblow setup` call. The runtime falls back to
`~/.pufferblow/config.toml` only if the env var is absent or empty.

### SFU bootstrap

`RTC_BOOTSTRAP_SECRET` is the HMAC secret the SFU presents when it
calls `/api/internal/v1/voice/bootstrap-config` on the API. The API
needs to know the same secret — it's written into
`~/.pufferblow/config.toml` by `pufferblow setup --setup-media-sfu`.
The compose file mounts the `pufferblow_data` volume on both services
so they share that file.

### TURN

`PUFFERBLOW_TURN_USERNAME` / `PUFFERBLOW_TURN_PASSWORD` are the
long-term credentials coturn advertises. Set them to long random
values and make sure they match what the Pufferblow API hands back in
its `ice_servers` bootstrap response (see `[voice]` in
`config.toml`). Without TURN, clients behind symmetric NAT (mobile,
many corporate networks) will fail to connect to voice channels.

### Ports

| Port range          | Service             | Notes                              |
| ------------------- | ------------------- | ---------------------------------- |
| `7575/tcp`          | pufferblow-server   | API + WS                           |
| `8787/tcp`          | media-sfu           | WebRTC signaling                   |
| `3478/tcp` + `udp`  | coturn              | TURN/STUN                          |
| `49160-49200/udp`   | coturn              | TURN relay range                   |
| `50000-50199/udp`   | media-sfu           | RTC media (override via `.env`)    |

## Persistent state

Two named volumes:

- `pufferblow_data` → `/root/.pufferblow` on the server + SFU
  (config.toml, local storage backend if used).
- `pufferblow_postgres` → `/var/lib/postgresql/data`.

Back up both volumes regularly. Re-creating the stack without those
volumes wipes user accounts, messages, and uploaded media.

## Healthchecks

`pufferblow-server` exposes `/healthz` and `/readyz`. The compose file
uses `/readyz` in its healthcheck so `media-sfu`'s
`depends_on: condition: service_healthy` only proceeds after the API
has finished bootstrap (DB connect + manager wiring) — otherwise the
SFU's bootstrap fetch would race the API and fail.

## Troubleshooting

- **`pufferblow-server` keeps restarting**: check
  `docker compose logs pufferblow-server`. Most often a missing
  `PUFFERBLOW_DATABASE_URI` or a Postgres password mismatch.
- **`media-sfu` errors with "bootstrap config fetch failed"**:
  `RTC_BOOTSTRAP_SECRET` in `.env` does not match the
  `[media-sfu] bootstrap_secret` in `config.toml`. Rerun
  `pufferblow setup --setup-media-sfu` and copy the printed value.
- **Voice connects but no audio between two browsers**: confirm
  `RTC_UDP_PORT_MIN`/`MAX` are open on the host firewall. If clients
  are on different networks behind NAT, also confirm TURN credentials
  are configured and reachable on `3478`.
