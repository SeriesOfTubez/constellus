# capture-browser — headless Chromium whose only network path is capture-proxy
# (planning#280 S5b-1). Chromium ONLY: no Firefox / WebKit in the image.
FROM python:3.12-slim@sha256:12316debbfb86890f6b2d825820612741ba527ad5a44e3902759141d572bfe8f

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.txt .

# `--only-shell` installs chromium-headless-shell only (no full Chrome, no other
# engines); `--with-deps` pulls just the OS libraries it links against. apt lists
# are cleared in the same layer.
RUN pip install --no-cache-dir --root-user-action=ignore -r requirements.txt \
    && playwright install --with-deps --only-shell chromium \
    && rm -rf /var/lib/apt/lists/* /root/.cache \
    && chmod -R a+rX /ms-playwright \
    && python -m pip uninstall -y --root-user-action=ignore pip setuptools wheel

# Shared spool group (gid 10050, docs/architecture/capture-spool.md): the backend
# and this worker both read/write /spool through it. 2770 = setgid, group-rw, no
# world access. Whoever creates a directory sets its mode explicitly.
RUN groupadd --gid 10050 capture-spool \
    && useradd --uid 10001 --create-home --shell /bin/false --groups capture-spool capture \
    && mkdir /spool /spool/jobs /spool/claimed /spool/results \
    && chown 10001:10050 /spool /spool/jobs /spool/claimed /spool/results \
    && chmod 2770 /spool /spool/jobs /spool/claimed /spool/results

COPY capture/ capture/

USER 10001
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import playwright"]
CMD ["python", "-m", "capture.worker"]
