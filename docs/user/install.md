# Install your own server

This is the **Docker-first** quickstart. If you're standing up
Pufferblow for the first time, this is the path that will work
the most reliably with the least typing.

If you want to develop against the server, see the
[from-source path](#from-source-for-developers) at the bottom.

## What you need

- A Linux host (any modern distro) or macOS with Docker. A small
  VPS with **2 GB RAM and 10 GB disk** is enough for a community
  of a few dozen people; scale up as needed.
- **Docker Engine** + **Docker Compose v2** installed. Test with
  `docker compose version`. If you don't have either, follow the
  official Docker install docs for your OS.
- A **domain or static IP** you can point clients at. Optional
  for testing on `localhost`, required for federation.
- About **15 minutes**.

## 1. Get the repo

```bash
git clone https://github.com/PufferBlow/pufferblow.git
cd pufferblow
```

## 2. Configure your `.env`

The Compose stack reads secrets and ports from a `.env` file in
the repo root. Start from the template:

```bash
cp .env.server.example .env
```

Open `.env` in your editor and replace **every** value that
starts with `change-me-...`. The important ones:

| Variable | What it is |
| --- | --- |
| `POSTGRES_PASSWORD` | Database password. Long, random. |
| `RTC_BOOTSTRAP_SECRET` | Shared HMAC between the API and the voice SFU. |
| `PUFFERBLOW_TURN_USERNAME` / `PUFFERBLOW_TURN_PASSWORD` | TURN credentials. Required for clients behind strict NAT (mobile, corporate). |
| `PUFFERBLOW_JWT_SECRET` | Signs auth tokens. Long, random. |

!!! warning "Don't skip the secrets"
    A default `change-me-...` left in production is a fresh-air
    invitation. Generate each one with
    `openssl rand -hex 32` or `python -c "import secrets; print(secrets.token_hex(32))"`.

## 3. Bring up the stack

```bash
docker compose --env-file .env -f docker-compose.prod.server.yml up -d --build
```

This starts four services:

- **`postgres`** — the database.
- **`pufferblow-server`** — the FastAPI API at port `7575`.
- **`media-sfu`** — the WebRTC voice forwarder at port `8787`.
- **`coturn`** — TURN/STUN relay at port `3478`.

First boot takes a minute or two — the API image is built from
source, then waits for Postgres to report healthy, then the SFU
fetches its bootstrap config from the API. Watch the boot:

```bash
docker compose logs -f
```

When everything has settled you should see the API answering
`/readyz` and the SFU saying it received bootstrap config.

## 4. Create the owner account

The Compose stack provisions the database automatically, but you
still need an admin account to log in. Run the setup wizard
inside the running container:

```bash
docker compose exec pufferblow-server pufferblow setup
```

Pick **Option 1 (full setup)** when prompted; the database
section is already configured, so it'll skip ahead to creating
the server identity and the owner account. **Save the auth
token it prints at the end** — you'll need it the first time
you sign in.

## 5. Point a client at it

The official client (Electron desktop or web) lives in
[`PufferBlow/client`](https://github.com/PufferBlow/client). Use
the prebuilt installer or run it from source; on the login
screen, set the **home instance** field to your server's URL
(e.g. `https://chat.example.com` or `http://1.2.3.4:7575` for a
local test).

Sign in with the username and password you created in step 4.

## 6. What to read next

- **[v1.0 release notes](../operator/release-notes-v1.0.md)** —
  what ships in v1.0 and what's deferred. Read this before
  inviting users so you don't surprise them.
- **[Operator guide](../operator/index.md)** — backups,
  federation, secret rotation, audit log, the CLI surface.
- **[Server architecture](../developer/architecture.md)** —
  how the pieces fit together if you're curious or planning to
  extend the server.

## Troubleshooting

**`pufferblow-server` keeps restarting.**

`docker compose logs pufferblow-server` is the first stop. The
two common causes:

- `PUFFERBLOW_DATABASE_URI` is unset or your Postgres password
  doesn't match `POSTGRES_PASSWORD`. Both sides of the password
  are in `.env`; they have to be identical.
- The container can't reach Postgres. The Compose healthcheck
  prevents this in steady state, but a stale volume from a
  previous `up` can wedge it — `docker compose down -v` and try
  again (note: `-v` **destroys data**; don't run that on a
  production stack with real users).

**`media-sfu` errors with "bootstrap config fetch failed".**

`RTC_BOOTSTRAP_SECRET` in `.env` doesn't match the
`[media-sfu] bootstrap_secret` in the API's `config.toml`.
Rerun the setup wizard:

```bash
docker compose exec pufferblow-server pufferblow setup --setup-media-sfu
```

and copy the printed value into `.env`. Then restart the SFU:

```bash
docker compose restart media-sfu
```

**Voice connects but no audio.**

Open `RTC_UDP_PORT_MIN`/`MAX` on the host firewall — by default
the SFU advertises ports `50000-50199/udp`. Clients on
different networks behind NAT also need TURN credentials that
actually work; test the relay from the same network as the
failing client.

**Other clients can't reach the server.**

- Check the host firewall — Ubuntu's UFW often blocks `7575`
  out of the box: `sudo ufw allow 7575`.
- If you're behind a reverse proxy, terminate TLS there and
  forward to `:7575` over HTTP. Don't expose the FastAPI server
  directly to the internet without TLS.

For deeper diagnostic work, the
[Operator guide](../operator/index.md) covers logs, the audit
table, blocked IPs, and federation debugging in much more
detail.

## From source (for developers)

If you're hacking on the server rather than running it, skip
Docker:

```bash
git clone https://github.com/PufferBlow/pufferblow.git
cd pufferblow
poetry install
poetry run pufferblow setup
poetry run pufferblow serve
```

You'll need a Postgres instance reachable from your machine —
either install Postgres locally or run just the `postgres`
service from the Compose file:

```bash
docker compose -f docker-compose.prod.server.yml up -d postgres
```

See [`CONTRIBUTING.md`](https://github.com/PufferBlow/pufferblow/blob/main/CONTRIBUTING.md)
for the rest of the dev workflow — running tests, lint, and the
commit message conventions.
