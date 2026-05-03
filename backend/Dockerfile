# ── Stage 1: build frontend ───────────────────────────────────────────────────
FROM node:22-slim AS frontend-builder
WORKDIR /frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
# Vite outputs to backend/static; we redirect to /build/static so the runtime stage can copy it
RUN npm run build -- --outDir /build/static

# ── Stage 2: build Python deps ────────────────────────────────────────────────
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

# ── Stage 3: runtime ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libxmlsec1-openssl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --no-create-home --shell /bin/false sextant

COPY --from=py-builder /install /usr/local
COPY backend/app/ app/
COPY --from=frontend-builder /build/static/ static/

USER sextant
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
