# Docker Compose Setup

## Services

```yaml
services:
  backend   # FastAPI — port 8000
  frontend  # React/Vite — port 3000
  db        # TimescaleDB (PostgreSQL 16) — port 5432
  migrate   # Runs Alembic migrations on startup, then exits
```

## Dev override

The `docker-compose.override.yml` file (gitignored) adds the Docker socket mount needed for Nuclei scanning. Create it locally:

```yaml
# docker-compose.override.yml
services:
  backend:
    user: root
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
```

Docker Compose merges this automatically — no command changes needed.

## Common commands

```bash
# Start all services
docker compose up -d

# View logs
docker compose logs -f backend

# Rebuild after code changes
docker compose up -d --build backend

# Stop everything
docker compose down

# Wipe database
docker compose down -v
```
