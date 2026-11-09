# ── Stage 1: build Python deps ────────────────────────────────────────────────
FROM python:3.12-slim@sha256:4840d514c583a4d3d8cad3940e68dee6f0f6f3635c12fcd0a3d74c21a5b93a54 AS py-builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --root-user-action=ignore --prefix=/install -r requirements.txt

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM python:3.12-slim@sha256:4840d514c583a4d3d8cad3940e68dee6f0f6f3635c12fcd0a3d74c21a5b93a54 AS runtime
WORKDIR /app

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Shared spool group (gid 10050): the proxy writes per-capture logs to /proxylog
# which the backend reads. See docs/architecture/capture-spool.md.
# apt-get upgrade applies Debian security updates the pinned base predates (Trivy gates
# on them; same rule as backend/Dockerfile).
RUN apt-get update && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10050 capture-spool \
    && useradd --uid 10001 --create-home --shell /bin/false --groups capture-spool capture-proxy \
    && mkdir /proxylog \
    && chown 10001:10050 /proxylog \
    && chmod 2770 /proxylog \
    && mkdir /capture_config \
    && chown 10001:10050 /capture_config \
    && chmod 2770 /capture_config

COPY --from=py-builder /install /usr/local
# ip_blocklist.py is byte-identical to backend/app/core/ip_blocklist.py and
# scanner-worker/ip_blocklist.py and MUST be copied in — proxy.py imports it at
# module scope, so a missing copy fails the container at startup rather than
# silently degrading the guard. tests/test_blocklist_parity.py fails if the
# trees' copies diverge.
COPY ip_blocklist.py .
COPY proxy.py .
COPY log_s3.py .
COPY store_auth.py .

RUN python -m pip uninstall -y --root-user-action=ignore pip setuptools wheel

USER 10001
EXPOSE 3128
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import socket; socket.create_connection(('127.0.0.1', 3128), 3).close()"]
CMD ["python", "-u", "proxy.py"]
