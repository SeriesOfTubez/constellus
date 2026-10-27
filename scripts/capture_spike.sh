#!/usr/bin/env bash
# Egress spike for capture-browser (planning#280 S5b-1): proves ALL browser traffic
# goes through capture-proxy and that blocked/private fetches are ATTEMPTED and
# BLOCKED AT THE PROXY. Re-runnable; tears its own compose project down on exit.
#
#   bash scripts/capture_spike.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export COMPOSE_PROJECT_NAME=constellus-s5b1   # never collides with the dev stack
export CAPTURE_PROXY_TOKEN="${CAPTURE_PROXY_TOKEN:-$(openssl rand -hex 32)}"
DC=(docker compose --profile capture)
WORK="$(mktemp -d)"
cleanup() { "${DC[@]}" down -v --remove-orphans >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT

RUN_ID="spk$(openssl rand -hex 4)"
CERT_ID="spkcert$(openssl rand -hex 4)"

"${DC[@]}" build capture-proxy capture-browser >/dev/null
"${DC[@]}" up -d --wait capture-proxy >/dev/null

# In-container runs: the spike dir is mounted read-only; the image itself only holds capture/.
run_in_browser() {
  "${DC[@]}" run --rm -T -e PYTHONPATH=/app -v "$ROOT/capture-browser/spike:/spike:ro" capture-browser "$@" 2>"$WORK/stderr.last"
}
extract() { sed -n 's/^SPIKE_JSON=//p' | tail -n 1; }

run_in_browser python /spike/spike.py browser --capture-id "$RUN_ID" | extract >"$WORK/browser.json" \
  || { cat "$WORK/stderr.last" >&2; echo "browser run failed" >&2; exit 2; }
run_in_browser python /spike/spike.py net | extract >"$WORK/net.json" \
  || { cat "$WORK/stderr.last" >&2; echo "net run failed" >&2; exit 2; }
run_in_browser sh -c "python -m capture.run --capture-id $CERT_ID --url https://example.com/ --out /tmp/o >&2 && cat /tmp/o/result.json" >"$WORK/cert.json" \
  || { cat "$WORK/stderr.last" >&2; echo "cert run failed" >&2; exit 2; }

"${DC[@]}" logs --no-log-prefix capture-proxy >"$WORK/proxy.log" 2>&1

python3 "$ROOT/capture-browser/spike/evaluate.py" \
  "$WORK/browser.json" "$WORK/net.json" "$WORK/cert.json" "$WORK/proxy.log" "$RUN_ID" "$CERT_ID"
