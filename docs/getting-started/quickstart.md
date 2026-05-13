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

## 3. Create the dev override file

The Docker socket mount (required for Nuclei scanning) lives in a gitignored override file:

```bash
cat > docker-compose.override.yml << 'EOF'
services:
  backend:
    user: root
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
EOF
```

## 4. Start the stack

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

## 5. Complete setup

Navigate to [http://localhost:3000](http://localhost:3000) and follow the setup wizard to create your admin account.
