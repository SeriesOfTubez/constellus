#!/usr/bin/env bash
# kind-lab.sh: local Kubernetes lab for the capture stack (planning#324). TEST ONLY.
#
#   scripts/kind-lab.sh up              create the kind cluster, build + load images, apply deploy/k8s/lab
#   scripts/kind-lab.sh e2e [url] [--count N]
#                                       one real capture through proxy + RustFS (scripts/kind_lab_e2e.py)
#   scripts/kind-lab.sh verify          prove NetworkPolicy is ENFORCED (PASS/FAIL per path)
#   scripts/kind-lab.sh limits-check    prove the proxy re-reads the limits ConfigMap live
#   scripts/kind-lab.sh status          pods, restarts, network policies
#   scripts/kind-lab.sh down [--purge]  delete the cluster (--purge also removes the state dir)
#
# Secrets (RustFS root key, proxy HMAC key) are generated once into
# ${CONSTELLUS_LAB_STATE:-$HOME/.cache/constellus-kind-lab}/secrets.env (0600, outside the
# repo). Values are never printed and never placed on a command line.
set -eu

CLUSTER=constellus-lab
CTX="kind-$CLUSTER"
NS=constellus
# kind v0.33.0 default node image (Kubernetes v1.37.0), pinned by digest from its release notes.
NODE_IMAGE='kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5'

REPO=$(cd "$(dirname "$0")/.." && pwd)
STATE=${CONSTELLUS_LAB_STATE:-$HOME/.cache/constellus-kind-lab}
SECRETS="$STATE/secrets.env"

kc() { kubectl --context "$CTX" "$@"; }
kn() { kubectl --context "$CTX" -n "$NS" "$@"; }

ensure_state() {
  umask 077
  mkdir -p "$STATE"
  chmod 700 "$STATE"
  if [ ! -f "$SECRETS" ]; then
    {
      echo "RUSTFS_ACCESS_KEY=$(openssl rand -hex 10)"
      echo "RUSTFS_SECRET_KEY=$(openssl rand -hex 32)"
      echo "CAPTURE_PROXY_KEY=$(openssl rand -hex 32)"
    } > "$SECRETS"
  fi
  chmod 600 "$SECRETS"
}

# Print one value from the secrets file to stdout (used only to feed files, never the terminal).
secret_val() { sed -n "s/^$1=//p" "$SECRETS"; }

# apply_secret NAME KEY=SOURCE...: build a 0600 env file in the state dir, apply, delete.
apply_secret() {
  name=$1; shift
  f="$STATE/.secret-$name.env"
  ( umask 077; : > "$f" )
  for pair in "$@"; do
    key=${pair%%=*}; src=${pair#*=}
    printf '%s=%s\n' "$key" "$(secret_val "$src")" >> "$f"
  done
  kn create secret generic "$name" --from-env-file="$f" --dry-run=client -o yaml | kn apply -f - >/dev/null
  rm -f "$f"
}

cmd_up() {
  ensure_state
  if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
    cfg="$STATE/kind-config.yaml"
    cat > "$cfg" <<CFG
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: $NODE_IMAGE
    extraMounts:
      - hostPath: $REPO/capture-browser/seccomp.json
        containerPath: /var/lib/kubelet/seccomp/profiles/capture-browser.json
        readOnly: true
CFG
    kind create cluster --name "$CLUSTER" --config "$cfg" --wait 120s
  fi
  docker build -t constellus/capture-proxy:lab "$REPO/capture-proxy"
  docker build -t constellus/capture-browser:lab "$REPO/capture-browser"
  for img in constellus/capture-proxy:lab constellus/capture-browser:lab; do
    kind load docker-image --name "$CLUSTER" "$img"
  done
  # RustFS is NOT side-loaded: its image is a multi-platform index, and both
  # `kind load docker-image` and `docker save --platform | kind load image-archive`
  # produce an image the kubelet cannot start on Docker Desktop's containerd store
  # (digest not found / "import-<date>" name mismatch). The node pulls it from the
  # registry instead, BY DIGEST (content-verified), pinned in deploy/k8s/lab/rustfs.yaml.
  kc get namespace "$NS" >/dev/null 2>&1 || kc create namespace "$NS"
  apply_secret rustfs-root RUSTFS_ACCESS_KEY=RUSTFS_ACCESS_KEY RUSTFS_SECRET_KEY=RUSTFS_SECRET_KEY
  apply_secret capture-proxy-key CAPTURE_PROXY_KEY=CAPTURE_PROXY_KEY
  # LAB ONLY: the RustFS ROOT credentials fill both store secrets (one key, all roles).
  apply_secret capture-store-worker CAPTURE_S3_ACCESS_KEY=RUSTFS_ACCESS_KEY CAPTURE_S3_SECRET_KEY=RUSTFS_SECRET_KEY
  apply_secret capture-store-proxy CAPTURE_S3_ACCESS_KEY=RUSTFS_ACCESS_KEY CAPTURE_S3_SECRET_KEY=RUSTFS_SECRET_KEY
  kc apply -k "$REPO/deploy/k8s/lab"
  # A changed image under the same tag needs a restart to be picked up.
  kn rollout restart deploy/capture-proxy deploy/capture-browser >/dev/null
  kn rollout status deploy/rustfs --timeout=180s
  kn rollout status deploy/capture-proxy --timeout=180s
  kn rollout status deploy/capture-browser --timeout=180s || true
  kn wait --for=jsonpath='{.status.phase}'=Running pod -l app.kubernetes.io/name=capture-browser --timeout=120s
  cmd_status
}

free_port() {
  "$REPO/backend/.venv/bin/python" - "$1" <<'PY'
import socket, sys
want = int(sys.argv[1])
for p in [want] + list(range(want + 1, want + 50)):
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", p))
        print(p)
        break
    except OSError:
        pass
    finally:
        s.close()
PY
}

# Start a background port-forward to rustfs; sets PF_PID and PORT. Caller must trap PF_PID.
start_pf() {
  PORT=$(free_port "${KIND_LAB_PORT:-19324}")
  kn port-forward svc/rustfs "$PORT:9000" >/dev/null 2>&1 &
  PF_PID=$!
  i=0
  while ! curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; do
    i=$((i + 1)); [ "$i" -gt 30 ] && { echo "port-forward did not come up" >&2; return 1; }
    sleep 1
  done
}

cmd_e2e() {
  ensure_state
  start_pf
  trap 'kill "$PF_PID" 2>/dev/null || true' EXIT
  rc=0
  (
    set -a; . "$SECRETS"; set +a
    KIND_LAB_ENDPOINT="http://127.0.0.1:$PORT" KIND_LAB_CONTEXT="$CTX" \
      exec "$REPO/backend/.venv/bin/python" "$REPO/scripts/kind_lab_e2e.py" "$@"
  ) || rc=$?
  kill "$PF_PID" 2>/dev/null || true
  wait "$PF_PID" 2>/dev/null || true
  trap - EXIT
  return $rc
}

cmd_status() {
  kn get pods -o wide
  kn get networkpolicy
}

# --- verify -------------------------------------------------------------------
FAILS=0
report() { # report PASS|FAIL description
  printf '%s  %s\n' "$1" "$2"
  [ "$1" = PASS ] || FAILS=$((FAILS + 1))
}

PYCONN='import os, socket, sys
h, p = sys.argv[1], int(sys.argv[2])
if h == "APISERVER":
    h, p = os.environ["KUBERNETES_SERVICE_HOST"], int(os.environ["KUBERNETES_SERVICE_PORT"])
s = socket.socket()
s.settimeout(5)
try:
    s.connect((h, p))
    print("OPEN")
except OSError:
    print("CLOSED")'

# probe TARGET(pod|deploy/x) HOST PORT -> prints OPEN or CLOSED (retries while the pod restarts)
probe() {
  tgt=$1; host=$2; port=$3; i=0
  while :; do
    if out=$(kn exec "$tgt" -- python -c "$PYCONN" "$host" "$port" 2>/dev/null); then
      printf '%s' "$out"; return 0
    fi
    i=$((i + 1)); [ "$i" -gt 30 ] && { printf 'EXECFAIL'; return 0; }
    sleep 2
  done
}

expect() { # expect OPEN|CLOSED description target host port
  want=$1; desc=$2; shift 2
  got=$(probe "$@")
  if [ "$got" = "$want" ]; then report PASS "$desc ($got)"; else report FAIL "$desc (wanted $want, got $got)"; fi
}

cmd_verify() {
  B=deploy/capture-browser; P=deploy/capture-proxy
  expect CLOSED "a. browser -> example.com:80 direct denied" $B example.com 80
  expect OPEN   "b. browser -> capture-proxy:3128 allowed" $B capture-proxy 3128
  expect OPEN   "c. browser -> rustfs:9000 allowed" $B rustfs 9000
  expect CLOSED "d. browser -> API server denied" $B APISERVER 0
  expect OPEN   "e. proxy -> example.com:80 allowed" $P example.com 80
  expect CLOSED "f. proxy -> API server denied" $P APISERVER 0
  # g. a pod with no capture labels
  kn delete pod netpol-probe --ignore-not-found --wait=true >/dev/null
  kn run netpol-probe --image=constellus/capture-proxy:lab --image-pull-policy=Never --restart=Never \
    --labels=app.kubernetes.io/name=netpol-probe --command -- sleep 300 >/dev/null
  trap 'kn delete pod netpol-probe --ignore-not-found --wait=false >/dev/null 2>&1 || true' EXIT
  kn wait --for=condition=Ready pod/netpol-probe --timeout=60s >/dev/null
  # By pod IP, not name: the unlabelled pod has no DNS egress either, so a name would
  # fail to resolve and "denied" would pass for the wrong reason.
  rip=$(kn get pod -l app.kubernetes.io/name=rustfs -o jsonpath='{.items[0].status.podIP}')
  pip=$(kn get pod -l app.kubernetes.io/name=capture-proxy -o jsonpath='{.items[0].status.podIP}')
  expect CLOSED "g1. unlabelled pod -> rustfs pod IP:9000 denied" pod/netpol-probe "$rip" 9000
  expect CLOSED "g2. unlabelled pod -> capture-proxy pod IP:3128 denied" pod/netpol-probe "$pip" 3128
  kn delete pod netpol-probe --ignore-not-found --wait=false >/dev/null
  trap - EXIT
  for t in $B $P; do
    i=0
    while :; do
      if out=$(kn exec "$t" -- python -c "import os; print('ABSENT' if not os.path.exists('/var/run/secrets/kubernetes.io') else 'PRESENT')" 2>/dev/null); then break; fi
      i=$((i + 1)); [ "$i" -gt 30 ] && { out=EXECFAIL; break; }
      sleep 2
    done
    if [ "$out" = ABSENT ]; then report PASS "h. $t has no service-account token dir ($out)"; else report FAIL "h. $t service-account token dir ($out)"; fi
  done
  if [ "$FAILS" -gt 0 ]; then echo "verify: $FAILS check(s) FAILED"; return 1; fi
  echo "verify: all checks passed"
}

# --- limits-check ---------------------------------------------------------------
put_limits() { # put_limits CONNECT IDLE MAX
  f="$STATE/.limits.json"
  ( umask 077; printf '{"version":1,"connect_timeout_s":%s,"idle_timeout_s":%s,"max_connections":%s}\n' "$1" "$2" "$3" > "$f" )
  kn create configmap capture-proxy-limits --from-file=proxy_limits.json="$f" --dry-run=client -o yaml | kn apply -f - >/dev/null
  rm -f "$f"
}

wait_limits_file() { # wait_limits_file CONNECT: until the mounted file shows that connect value
  i=0
  while ! kn exec deploy/capture-proxy -- python -c "import sys; sys.exit(0 if '\"connect_timeout_s\":$1,' in open('/capture_config/..data/proxy_limits.json').read() else 1)" 2>/dev/null; do
    i=$((i + 1)); [ "$i" -gt 60 ] && { echo "kubelet did not sync the ConfigMap within ~180 s" >&2; return 1; }
    sleep 3
  done
}

check_limits_logged() { # check_limits_logged CONNECT IDLE MAX
  if kn logs deploy/capture-proxy | grep -q "limits source=file connect_timeout_s=$1 idle_timeout_s=$2 max_connections=$3"; then
    report PASS "proxy logged limits source=file connect=$1 idle=$2 max=$3"
  else
    report FAIL "proxy did not log limits source=file connect=$1 idle=$2 max=$3"
  fi
}

cmd_limits_check() {
  ensure_state
  start=$(date +%s)
  put_limits 17 123 77
  wait_limits_file 17
  echo "synced after $(( $(date +%s) - start )) s"
  cmd_e2e "$@" >/dev/null
  check_limits_logged 17 123 77
  start=$(date +%s)
  put_limits 19 131 79
  wait_limits_file 19
  echo "second update synced after $(( $(date +%s) - start )) s"
  cmd_e2e "$@" >/dev/null
  check_limits_logged 19 131 79
  # The symlink path is refused (O_NOFOLLOW); the ..data path is read.
  kn exec deploy/capture-proxy -- python -c '
import proxy
d = proxy.Limits(proxy.CONNECT_TIMEOUT_S, proxy.IDLE_TIMEOUT_S, proxy.MAX_CONNECTIONS)
for path in ("/capture_config/proxy_limits.json", "/capture_config/..data/proxy_limits.json"):
    src = proxy.LimitsSource(path, d)
    src.current()
    print("  ", path, "->", src._announced[0])
' 2>&1 | grep -v "capture-proxy: limits source"
  kn delete configmap capture-proxy-limits --ignore-not-found >/dev/null
  [ "$FAILS" -eq 0 ] || return 1
}

cmd_down() {
  kind delete cluster --name "$CLUSTER"
  if [ "${1:-}" = "--purge" ]; then rm -rf "$STATE"; echo "state dir removed"; else echo "state dir kept: $STATE"; fi
}

sub=${1:-}
[ $# -gt 0 ] && shift
case "$sub" in
  up) cmd_up ;;
  e2e) cmd_e2e "$@" ;;
  verify) cmd_verify ;;
  limits-check) cmd_limits_check "$@" ;;
  status) cmd_status ;;
  down) cmd_down "$@" ;;
  *) echo "usage: $0 {up|e2e [url] [--count N]|verify|limits-check|status|down [--purge]}" >&2; exit 2 ;;
esac
