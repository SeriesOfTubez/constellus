# Docker Compose Setup

## Services

```yaml
services:
  backend   # FastAPI — port 8000
  frontend  # React/Vite — port 3000
  db        # TimescaleDB (PostgreSQL 16) — port 5432
  migrate   # Runs Alembic migrations on startup, then exits
```

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

## Nuclei templates

The Nuclei binary is bundled in the backend image and runs directly — no Docker socket or privileged access required. On first scan Nuclei downloads its template library (~300MB). To persist templates across container restarts, add a volume:

```yaml
# docker-compose.override.yml
services:
  backend:
    volumes:
      - nuclei_templates:/home/constellus/.local

volumes:
  nuclei_templates:
```
