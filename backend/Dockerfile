# ── Stage 1: build Python deps ────────────────────────────────────────────────
FROM python:3.12-slim AS py-builder
WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libxmlsec1-dev \
    libxml2-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libxmlsec1-openssl \
    curl \
    && curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-27.4.1.tgz \
    | tar -xz --strip-components=1 -C /usr/local/bin docker/docker \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -g 999 docker-host || true \
    && useradd --no-create-home --shell /bin/false --groups docker-host constellus

COPY --from=py-builder /install /usr/local
COPY backend/app/ app/
COPY backend/alembic/ alembic/
COPY backend/alembic.ini .

USER constellus
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
