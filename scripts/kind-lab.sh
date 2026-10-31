#!/usr/bin/env bash
# kind-lab.sh: local Kubernetes lab for the capture stack and the backend (planning#324). TEST ONLY.
#
#   scripts/kind-lab.sh up              create the kind cluster, build + load images (proxy, browser,
#                                       backend), apply deploy/k8s/lab (in-cluster Postgres + RustFS)
#   scripts/kind-lab.sh e2e [url] [--count N]
#                                       one real capture through proxy + RustFS (scripts/kind_lab_e2e.py)
#   scripts/kind-lab.sh verify          prove NetworkPolicy is ENFORCED and the backend RBAC is tight (PASS/FAIL)
#   scripts/kind-lab.sh limits-check    change a setting through the backend API, watch it write the
#                                       limits ConfigMap, then watch the proxy re-read it
#   scripts/kind-lab.sh status          pods, deployments, limits ConfigMap value, network policies
#   scripts/kind-lab.sh down [--purge]  delete the cluster (--purge also removes the state dir)
#
# Secrets (RustFS root key, proxy HMAC key, DB password, backend SECRET_KEY, lab admin
# password) are generated once, per key, into
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

# ensure_key KEY VALUE: append KEY=VALUE unless the file already has a KEY= line, so a
# secrets file from an earlier slice gains only the new keys and keeps its old ones.
ensure_key() { grep -q "^$1=" "$SECRETS" || printf '%s=%s\n' "$1" "$2" >> "$SECRETS"; }

ensure_state() {
  umask 077
  mkdir -p "$STATE"
  chmod 700 "$STATE"
  touch "$SECRETS"
  chmod 600 "$SECRETS"
  ensure_key RUSTFS_ACCESS_KEY "$(openssl rand -hex 10)"
  ensure_key RUSTFS_SECRET_KEY "$(openssl rand -hex 32)"
  ensure_key CAPTURE_PROXY_KEY "$(openssl rand -hex 32)"
  ensure_key LAB_DB_PASSWORD "$(openssl rand -hex 24)"
  ensure_key BACKEND_SECRET_KEY "$(openssl rand -hex 32)"
  ensure_key LAB_ADMIN_PASSWORD "$(openssl rand -hex 16)"
  ensure_key LAB_DB_USER constellus
  ensure_key LAB_DB_NAME constellus
  ensure_key LAB_ADMIN_USERNAME lab-admin
  # example.com, not .invalid: the backend validates with EmailStr, which rejects
  # special-use domains such as .invalid.
  ensure_key LAB_ADMIN_EMAIL lab-admin@example.com
}

# Print one value from the secrets file to stdout (used only to feed files, never the terminal).
secret_val() { sed -n "s/^$1=//p" "$SECRETS"; }

# secret_file_new NAME: create an empty 0600 env file in the state dir, print its path.
secret_file_new() {
  f="$STATE/.secret-$1.env"
  ( umask 077; : > "$f" )
  printf '%s' "$f"
}

# secret_file_add FILE KEY VALUE: append KEY=VALUE. printf is a shell builtin, so VALUE
# (which may be composed from secrets) never appears on any command line.
secret_file_add() { printf '%s=%s\n' "$2" "$3" >> "$1"; }

# secret_file_apply NAME FILE: create/update the Secret from the env file, then delete it.
secret_file_apply() {
  kn create secret generic "$1" --from-env-file="$2" --dry-run=client -o yaml | kn apply -f - >/dev/null
  rm -f "$2"
}

# apply_secret NAME KEY=SOURCE...: each value is read from the secrets file key SOURCE.
apply_secret() {
  name=$1; shift
  f=$(secret_file_new "$name")
  for pair in "$@"; do
    secret_file_add "$f" "${pair%%=*}" "$(secret_val "${pair#*=}")"
  done
  secret_file_apply "$name" "$f"
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
  # The backend's build context is the repo root, as in Compose.
  docker build -t constellus/backend:lab -f "$REPO/backend/Dockerfile" "$REPO"
  for img in constellus/capture-proxy:lab constellus/capture-browser:lab constellus/backend:lab; do
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
  # LAB ONLY: the RustFS root credentials also fill the backend's store secret.
  apply_secret capture-store-backend CAPTURE_S3_ACCESS_KEY=RUSTFS_ACCESS_KEY CAPTURE_S3_SECRET_KEY=RUSTFS_SECRET_KEY
  apply_secret lab-postgres POSTGRES_USER=LAB_DB_USER POSTGRES_PASSWORD=LAB_DB_PASSWORD POSTGRES_DB=LAB_DB_NAME
  # backend-env carries a COMPOSED value (the DB URL), built in the 0600 file, never on argv.
  f=$(secret_file_new backend-env)
  secret_file_add "$f" DATABASE_URL "postgresql://$(secret_val LAB_DB_USER):$(secret_val LAB_DB_PASSWORD)@postgres:5432/$(secret_val LAB_DB_NAME)"
  secret_file_add "$f" SECRET_KEY "$(secret_val BACKEND_SECRET_KEY)"
  secret_file_apply backend-env "$f"
  kc apply -k "$REPO/deploy/k8s/lab"
  apply_apiserver_policy
  # A changed image under the same tag needs a restart to be picked up.
  kn rollout restart deploy/capture-proxy deploy/capture-browser deploy/backend >/dev/null
  kn rollout status deploy/rustfs --timeout=180s
  kn rollout status deploy/postgres --timeout=180s
  ensure_buckets
  # The migrate init container runs first, so this also proves the DB path and migrations.
  kn rollout status deploy/backend --timeout=300s
  kn rollout status deploy/capture-proxy --timeout=180s
  kn rollout status deploy/capture-browser --timeout=180s || true
  kn wait --for=jsonpath='{.status.phase}'=Running pod -l app.kubernetes.io/name=capture-browser --timeout=120s
  cmd_status
}

# The backend's API-server egress rule names the ENDPOINT address(es) and port from the
# `kubernetes` EndpointSlice, not the 10.96.0.1:443 ClusterIP: kindnet (like most CNIs)
# matches egress AFTER DNAT. The address differs per cluster, so the rule is generated
# here, not committed.
apply_apiserver_policy() {
  addrs=$(kc get endpointslices -n default -l kubernetes.io/service-name=kubernetes \
    -o jsonpath='{.items[*].endpoints[*].addresses[*]}')
  aport=$(kc get endpointslices -n default -l kubernetes.io/service-name=kubernetes \
    -o jsonpath='{.items[0].ports[0].port}')
  if [ -z "$addrs" ] || [ -z "$aport" ]; then
    echo "could not read the kubernetes EndpointSlice" >&2
    return 1
  fi
  out="$STATE/backend-egress-apiserver.yaml"
  {
    cat <<HDR
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-egress-apiserver
  namespace: $NS
  labels:
    app.kubernetes.io/part-of: constellus
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: backend
  policyTypes: [Egress]
  egress:
    - to:
HDR
    for a in $addrs; do
      case "$a" in *:*) mask=128 ;; *) mask=32 ;; esac
      echo "        - ipBlock: {cidr: $a/$mask}"
    done
    echo "      ports:"
    echo "        - {protocol: TCP, port: $aport}"
  } > "$out"
  kc apply -f "$out" >/dev/null
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

# start_pf SVC PORT HEALTH_PATH: background port-forward to svc/SVC:PORT; sets PF_PID and
# PORT (the local port). Caller must trap PF_PID.
start_pf() {
  PORT=$(free_port "${KIND_LAB_PORT:-19324}")
  kn port-forward "svc/$1" "$PORT:$2" >/dev/null 2>&1 &
  PF_PID=$!
  i=0
  while ! curl -fsS "http://127.0.0.1:$PORT$3" >/dev/null 2>&1; do
    i=$((i + 1)); [ "$i" -gt 30 ] && { echo "port-forward to $1 did not come up" >&2; return 1; }
    sleep 1
  done
}

# Create, idempotently, every bucket the lab uses (the backend needs its four to exist;
# lab-e2e-results belongs to the host-driven e2e check).
ensure_buckets() {
  start_pf rustfs 9000 /health
  trap 'kill "$PF_PID" 2>/dev/null || true' EXIT
  rc=0
  (
    set -a; . "$SECRETS"; set +a
    KIND_LAB_ENDPOINT="http://127.0.0.1:$PORT" "$REPO/backend/.venv/bin/python" - <<'PY'
import os
import botocore.session
from botocore.config import Config
from botocore.exceptions import ClientError

c = botocore.session.get_session().create_client(
    "s3",
    region_name="us-east-1",
    endpoint_url=os.environ["KIND_LAB_ENDPOINT"],
    aws_access_key_id=os.environ["RUSTFS_ACCESS_KEY"],
    aws_secret_access_key=os.environ["RUSTFS_SECRET_KEY"],
    config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
)
for b in ("lab-jobs", "lab-results", "lab-proxylog", "lab-images", "lab-e2e-results"):
    try:
        c.create_bucket(Bucket=b)
    except ClientError as e:
        if e.response.get("Error", {}).get("Code", "") not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            raise
print("buckets ensured")
PY
  ) || rc=$?
  kill "$PF_PID" 2>/dev/null || true
  wait "$PF_PID" 2>/dev/null || true
  trap - EXIT
  return $rc
}

cmd_e2e() {
  ensure_state
  start_pf rustfs 9000 /health
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
  kn get deploy
  v=$(kn get configmap capture-proxy-limits -o jsonpath='{.data.proxy_limits\.json}' 2>/dev/null || true)
  echo "capture-proxy-limits proxy_limits.json: ${v:-(unset)}"
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

rbac() { # rbac yes|no description VERB RESOURCE
  want=$1; desc=$2; shift 2
  got=$(kc auth can-i "$@" -n "$NS" --as="system:serviceaccount:$NS:backend" 2>/dev/null || true)
  if [ "$got" = "$want" ]; then report PASS "$desc ($got)"; else report FAIL "$desc (wanted $want, got ${got:-error})"; fi
}

cmd_verify() {
  B=deploy/capture-browser; P=deploy/capture-proxy; K=deploy/backend
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
  gip=$(kn get pod -l app.kubernetes.io/name=postgres -o jsonpath='{.items[0].status.podIP}')
  expect CLOSED "p. unlabelled pod -> postgres pod IP:5432 denied" pod/netpol-probe "$gip" 5432
  kn delete pod netpol-probe --ignore-not-found --wait=false >/dev/null
  trap - EXIT
  for tw in "$B:ABSENT" "$P:ABSENT" "$K:PRESENT"; do
    t=${tw%%:*}; want=${tw##*:}
    i=0
    while :; do
      if out=$(kn exec "$t" -- python -c "import os; print('PRESENT' if os.path.exists('/var/run/secrets/kubernetes.io') else 'ABSENT')" 2>/dev/null); then break; fi
      i=$((i + 1)); [ "$i" -gt 30 ] && { out=EXECFAIL; break; }
      sleep 2
    done
    # h (browser, proxy: ABSENT) and q (backend: PRESENT, it needs the token for the ConfigMap)
    if [ "$out" = "$want" ]; then report PASS "h/q. $t service-account token dir ($out)"; else report FAIL "h/q. $t service-account token dir (wanted $want, got $out)"; fi
  done
  # backend paths
  bpip=$(kn get pod -l app.kubernetes.io/name=backend -o jsonpath='{.items[0].status.podIP}')
  expect OPEN   "i. backend -> API server (endpoint address) allowed" $K APISERVER 0
  expect OPEN   "j. backend -> postgres:5432 allowed" $K postgres 5432
  expect OPEN   "k. backend -> rustfs:9000 allowed" $K rustfs 9000
  expect OPEN   "l. backend -> example.com:80 allowed" $K example.com 80
  expect CLOSED "m. backend -> capture-proxy pod IP:3128 denied" $K "$pip" 3128
  expect CLOSED "n. browser -> backend pod IP:8000 denied" $B "$bpip" 8000
  expect CLOSED "o. proxy -> backend pod IP:8000 denied" $P "$bpip" 8000
  # r. RBAC: `kubectl auth can-i` prints yes/no. The get on capture-proxy-limits (yes)
  # and the get on capture-store (no) are a self-checking pair: if the TYPE/NAME form
  # were not a name match, both would answer the same.
  rbac yes "r1. backend SA get configmaps/capture-proxy-limits" get configmaps/capture-proxy-limits
  rbac yes "r2. backend SA patch configmaps/capture-proxy-limits" patch configmaps/capture-proxy-limits
  rbac no  "r3. backend SA create configmaps" create configmaps
  rbac no  "r4. backend SA delete configmaps/capture-proxy-limits" delete configmaps/capture-proxy-limits
  rbac no  "r5. backend SA list configmaps" list configmaps
  rbac no  "r6. backend SA get configmaps/capture-store (other name)" get configmaps/capture-store
  rbac no  "r7. backend SA get secrets" get secrets
  if [ "$FAILS" -gt 0 ]; then echo "verify: $FAILS check(s) FAILED"; return 1; fi
  echo "verify: all checks passed"
}

# --- limits-check ---------------------------------------------------------------
# put_limits is gone: the lab no longer writes the ConfigMap by hand, the backend does.
# wait_cm CONNECT: until the ConfigMap's key shows that connect value (backend tick <= 10 s).
wait_cm() {
  i=0
  while ! kn get configmap capture-proxy-limits -o jsonpath='{.data.proxy_limits\.json}' 2>/dev/null | grep -q "\"connect_timeout_s\":$1,"; do
    i=$((i + 1)); [ "$i" -gt 15 ] && { echo "backend did not write the ConfigMap within 45 s" >&2; return 1; }
    sleep 3
  done
}

# Backend API helpers. Bodies and the token live in 0600 files, passed to curl as
# --data @file / -H @file, never on argv.
api_post() { # api_post PATH BODYFILE -> prints HTTP status; response body to $STATE/.api-resp
  curl -sS -o "$STATE/.api-resp" -w '%{http_code}' -H 'Content-Type: application/json' \
    --data "@$2" "http://127.0.0.1:$PORT$1"
}

api_login() {
  f="$STATE/.api-body.json"
  ( umask 077; printf '{"email":"%s","password":"%s","full_name":"Lab Admin"}' \
      "$(secret_val LAB_ADMIN_EMAIL)" "$(secret_val LAB_ADMIN_PASSWORD)" > "$f" )
  code=$(api_post /api/auth/setup "$f")
  case "$code" in
    201) echo "lab admin created" ;;
    403) echo "lab admin already exists" ;;
    *) echo "setup failed: HTTP $code" >&2; return 1 ;;
  esac
  code=$(api_post /api/auth/login "$f")
  [ "$code" = 200 ] || { echo "login failed: HTTP $code" >&2; return 1; }
  # The token goes straight from the response file into a header file; it never
  # passes through the shell.
  "$REPO/backend/.venv/bin/python" -I - "$STATE/.api-resp" "$STATE/.api-auth" <<'PY'
import json, os, sys
tok = json.load(open(sys.argv[1]))["access_token"]
fd = os.open(sys.argv[2], os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as fh:
    fh.write("Authorization: Bearer " + tok + "\n")
PY
  rm -f "$f" "$STATE/.api-resp"
}

api_put_limits() { # api_put_limits CONNECT IDLE MAX
  f="$STATE/.api-body.json"
  ( umask 077; printf '{"proxy_connect_timeout_seconds":%s,"proxy_idle_timeout_seconds":%s,"proxy_max_connections":%s}' \
      "$1" "$2" "$3" > "$f" )
  code=$(curl -sS -o /dev/null -w '%{http_code}' -X PUT -H 'Content-Type: application/json' \
    -H "@$STATE/.api-auth" --data "@$f" "http://127.0.0.1:$PORT/api/settings/capture")
  rm -f "$f"
  [ "$code" = 200 ] || { echo "PUT /api/settings/capture failed: HTTP $code" >&2; return 1; }
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
  start_pf backend 8000 /api/health
  trap 'kill "$PF_PID" 2>/dev/null || true; rm -f "$STATE/.api-auth" "$STATE/.api-body.json" "$STATE/.api-resp"' EXIT
  api_login
  for vals in "17 123 77" "19 131 79"; do
    read -r c_s i_s m_c <<EOF
$vals
EOF
    start=$(date +%s)
    api_put_limits "$c_s" "$i_s" "$m_c"
    wait_cm "$c_s"
    echo "ConfigMap written after $(( $(date +%s) - start )) s"
    wait_limits_file "$c_s"
    echo "proxy file synced after $(( $(date +%s) - start )) s"
    # A subshell: cmd_e2e sets and clears its own EXIT trap, which must not clear ours.
    ( cmd_e2e "$@" >/dev/null )
    check_limits_logged "$c_s" "$i_s" "$m_c"
  done
  # Put the defaults back through the API and wait for the ConfigMap to show them.
  api_put_limits 10 30 256
  wait_cm 10
  echo "defaults restored"
  # The symlink path is refused (O_NOFOLLOW); the ..data path is read.
  kn exec deploy/capture-proxy -- python -c '
import proxy
d = proxy.Limits(proxy.CONNECT_TIMEOUT_S, proxy.IDLE_TIMEOUT_S, proxy.MAX_CONNECTIONS)
for path in ("/capture_config/proxy_limits.json", "/capture_config/..data/proxy_limits.json"):
    src = proxy.LimitsSource(path, d)
    src.current()
    print("  ", path, "->", src._announced[0])
' 2>&1 | grep -v "capture-proxy: limits source"
  # The ConfigMap is NOT deleted: the capture base owns it.
  kill "$PF_PID" 2>/dev/null || true
  rm -f "$STATE/.api-auth" "$STATE/.api-body.json" "$STATE/.api-resp"
  trap - EXIT
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
  *) echo "usage: $0 {up|e2e [url] [--count N]|verify|limits-check [url] [--count N]|status|down [--purge]}" >&2; exit 2 ;;
esac
