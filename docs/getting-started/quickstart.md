# Quick Start

## Prerequisites

- Docker and Docker Compose
- Git

## 1. Clone the repository

```bash
git clone https://github.com/SeriesOfTubez/constellus.git
cd constellus
```

## 2. Configure environment

```bash
cp .env.example .env
```

Edit `.env` and set at minimum:

```env
SECRET_KEY=your-secret-key-here   # generate with: openssl rand -hex 32
```

## 3. Start the stack

```bash
docker compose up -d
```

This starts:

| Service | URL |
|---|---|
| Frontend | http://localhost:3000 |
| Backend API | http://localhost:8000 |
| API docs | http://localhost:8000/api/docs |
| Database | localhost:5432 |

## 4. Complete setup

Navigate to [http://localhost:3000](http://localhost:3000) and follow the setup wizard to create your admin account.

## Notes

- **Nuclei scanning** — the Nuclei binary is bundled in the backend image. No Docker socket or additional setup is required. On first scan, Nuclei will download its template library (~300MB) — this is normal and only happens once per container lifecycle.
- **Nuclei templates** — for persistent template storage across container restarts, mount a volume at `/home/constellus/.local`.
