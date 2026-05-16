# Developer guide

You're building against the Pufferblow API, hacking on the
server, or writing a client. This section is for you.

## Start here

- **[Server architecture](architecture.md)** — runtime layout,
  boot sequence, manager map, request pipeline, auth, federation,
  voice, storage. The canonical "how the server works" document.
- **[API reference](api-reference.md)** — auto-generated from
  the FastAPI app's OpenAPI schema. Includes how to view it on
  a running instance and how to regenerate the embedded copy.

## Coming next

The following pages land in subsequent commits as the docs
modernization continues:

- **Client** — the Electron / React client, deep-link protocol,
  auto-updater, voice DSP wiring, localStorage cache strategy.
- **SDK** — using `pypufferblow` to write bots and integrations.
- **Contributing internals** — manager pattern, adding a route,
  the testing layout.

## Outside this site

- Source: [`PufferBlow/pufferblow`](https://github.com/PufferBlow/pufferblow)
- Client: [`PufferBlow/client`](https://github.com/PufferBlow/client)
- Media SFU: [`PufferBlow/media-sfu`](https://github.com/PufferBlow/media-sfu)
- SDK: [`PufferBlow/pypufferblow`](https://github.com/PufferBlow/pypufferblow)
- Live API docs — `/docs` on any running instance (Swagger UI)
- Contributing flow:
  [`CONTRIBUTING.md`](https://github.com/PufferBlow/pufferblow/blob/main/CONTRIBUTING.md)
