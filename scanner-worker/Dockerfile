# ── Stage 1: build Python deps ────────────────────────────────────────────────
FROM python:3.12-slim AS py-builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --root-user-action=ignore --prefix=/install -r requirements.txt

# ── Stage 2: zgrab2 binary ───────────────────────────────────────────────────
# Built from pinned source (govulncheck-gated, SBOM + SLSA provenance) by
# github.com/SeriesOfTubez/constellus-binaries. Versioned tag + immutable digest.
FROM ghcr.io/seriesoftubez/zgrab2:master-e5172a7@sha256:e16ede0a7cb117d2c552e10c45d1c0d503d921dc12c218a8fc22fa822c5106df AS zgrab2-bin

# ── Stage 3: runtime ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime
WORKDIR /app

ARG NUCLEI_VERSION=3.8.0
ARG NAABU_VERSION=2.6.1
ARG HTTPX_VERSION=1.9.0
ARG TLSX_VERSION=1.2.2

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# libpcap is naabu's SYN-scan dependency. The container is granted NET_RAW
# (docker-compose cap_add) so naabu runs SYN scan instead of the less-accurate
# CONNECT scan fallback. libpcap must be present at runtime for this to work.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    unzip \
    libpcap0.8 \
    nmap \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/false scanner-worker

RUN curl -sSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    -o /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip nuclei -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip

RUN curl -sSL "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu_${NAABU_VERSION}_linux_amd64.zip" \
    -o /tmp/naabu.zip \
    && unzip /tmp/naabu.zip naabu -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/naabu \
    && rm /tmp/naabu.zip

RUN curl -sSL "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_amd64.zip" \
    -o /tmp/httpx.zip \
    && unzip /tmp/httpx.zip httpx -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/httpx \
    && rm /tmp/httpx.zip

RUN curl -sSL "https://github.com/projectdiscovery/tlsx/releases/download/v${TLSX_VERSION}/tlsx_${TLSX_VERSION}_linux_amd64.zip" \
    -o /tmp/tlsx.zip \
    && unzip /tmp/tlsx.zip tlsx -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/tlsx \
    && rm /tmp/tlsx.zip

COPY --from=zgrab2-bin /zgrab2 /usr/local/bin/zgrab2
RUN chmod +x /usr/local/bin/zgrab2

COPY --from=py-builder /install /usr/local
COPY main.py .

RUN python -m pip uninstall -y --root-user-action=ignore pip setuptools wheel

USER scanner-worker
EXPOSE 8001
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8001/health || exit 1
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]
