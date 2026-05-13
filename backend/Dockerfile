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
    unzip \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/false constellus

# Install Nuclei binary (runs as subprocess — no Docker socket needed)
RUN curl -sSL https://github.com/projectdiscovery/nuclei/releases/download/v3.8.0/nuclei_3.8.0_linux_amd64.zip \
    -o /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip nuclei -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip

COPY --from=py-builder /install /usr/local
COPY backend/app/ app/
COPY backend/alembic/ alembic/
COPY backend/alembic.ini .

# pip is not needed at runtime — remove it to eliminate its CVE surface
RUN python -m pip uninstall -y pip setuptools wheel

USER constellus
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
