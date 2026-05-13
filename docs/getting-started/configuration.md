# Configuration

All configuration is via environment variables in `.env`. Copy `.env.example` to get started.

## Required

| Variable | Description |
|---|---|
| `SECRET_KEY` | JWT signing key — generate with `openssl rand -hex 32` |
| `DATABASE_URL` | PostgreSQL connection string |

## Optional

| Variable | Default | Description |
|---|---|---|
| `SECRETS_PROVIDER` | `env` | Secrets backend: `env` or `db` |
| `ALLOWED_ORIGINS` | `http://localhost:3000` | CORS origins |

## Connector credentials

Connector API keys are configured through the Admin → Connectors UI and stored encrypted in the database. They do not need to be set in `.env`.
