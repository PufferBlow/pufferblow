# PufferBlow Server Production Docker

This repository contains the server-only production stack.

Files:
- `docker-compose.prod.server.yml`
- `Dockerfile.prod`
- `.env.server.example`

## Run

```bash
cp .env.server.example .env
docker compose --env-file .env -f docker-compose.prod.server.yml up -d --build
```

## Notes

- Stack includes PostgreSQL (`postgres` service).
- Persisted volumes:
  - `pufferblow_data` for `/root/.pufferblow`
  - `pufferblow_postgres` for PostgreSQL data
- Set strong values for:
  - `PUFFERBLOW_JWT_SECRET`
  - `PUFFERBLOW_STORAGE_SSE_KEY`
