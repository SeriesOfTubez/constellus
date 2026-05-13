# Contributing

## Development setup

```bash
git clone https://github.com/SeriesOfTubez/constellus.git
cd constellus
cp .env.example .env
pre-commit install          # activate local security hooks
docker compose up -d
```

## Pre-commit hooks

The repo uses [pre-commit](https://pre-commit.com) to block secrets and Dockerfile issues before they reach GitHub. Run `pre-commit install` once after cloning.

## Making changes

- Backend changes are hot-reloaded by uvicorn in dev mode
- Frontend changes are hot-reloaded by Vite
- Database schema changes require an Alembic migration: `alembic revision --autogenerate -m "description"`

## Pull requests

All PRs must pass the security pipeline (Gitleaks, Semgrep, Trivy, Checkov, Hadolint) and the docs build check before merging.
