# Kubernetes (page-capture stack)

`deploy/k8s/` holds kustomize manifests for the page-capture stack in S3 mode
(planning#324): the headless-Chromium `capture-browser` worker, the `capture-proxy`
egress proxy (slice 1) and the `backend` (slice 2), which produces the capture jobs
and writes the proxy limits. The scanner-worker is not deployed (planning#309). Design background:
[Page Capture Spool](../architecture/capture-spool.md).

| Path | What |
|---|---|
| `deploy/k8s/capture/` | **Base**, the production shape: both Deployments, the Service, the pre-created empty `capture-proxy-limits` ConfigMap, a default-deny NetworkPolicy plus the allow rules. No store, no Secret values, no RustFS. |
| `deploy/k8s/backend/` | **Base**, the production shape: includes `capture/`, adds the backend Deployment (migrate init container), Service, ServiceAccount, the get/patch Role and the egress policy. No DB, no store, no Secret values. |
| `deploy/k8s/lab/` | **Test-only overlay**: `backend/` plus an in-cluster RustFS, an in-cluster Postgres 18 and their NetworkPolicy rules. Never a production overlay. |

The bases on their own cannot reach a store, a database or the API server: the policy
fails closed, and those rules are deployment-specific.

## Local lab (kind)

```bash
scripts/kind-lab.sh up && scripts/kind-lab.sh e2e && scripts/kind-lab.sh down
```

Needs `kind`, `kubectl`, Docker, `curl`, `openssl` and `backend/.venv` (botocore). Other
subcommands: `verify` (proves NetworkPolicy is enforced for the capture pods and the
backend, and that the backend's RBAC is exactly get/patch on one ConfigMap; PASS/FAIL
per check), `limits-check` (changes a setting through the backend API, watches the
backend write the ConfigMap, then watches the proxy re-read it), `status`,
`e2e --count N`, `down --purge`.

- The cluster is `constellus-lab`, on the kind v0.33.0 default node image
  (Kubernetes v1.37.0) pinned by digest. kindnet enforces NetworkPolicy; the
  `verify` subcommand shows it rather than assuming it.
- The kind node mounts `capture-browser/seccomp.json` at
  `/var/lib/kubelet/seccomp/profiles/capture-browser.json`. On any real cluster the
  profile must be installed on every node that can run the browser (Chromium's own
  sandbox needs `clone`/`unshare`/`chroot`).
- Secrets are generated once into `~/.cache/constellus-kind-lab/secrets.env` (0600,
  outside the repo, never printed). **Lab only: the RustFS root key fills both
  `capture-store-worker` and `capture-store-proxy`, so one key plays all three
  roles.**
- The images `constellus/capture-proxy:lab`, `constellus/capture-browser:lab` and
  `constellus/backend:lab` are built from the working tree (the backend from the repo
  root, as Compose does) and loaded into the node. The RustFS image is pulled by
  the node, by digest (side-loading the multi-platform image fails on Docker
  Desktop's containerd store).
- **TEST ONLY: Postgres 18 in the cluster**, on an `emptyDir` (data is lost with the
  pod), credentials generated into the secrets file. The backend's Secret
  `backend-env` (`DATABASE_URL`, `SECRET_KEY`) is composed by the script in a 0600
  file, never on a command line. The `migrate` init container runs
  `alembic upgrade head` before the backend starts.
- **Lab admin.** `limits-check` creates the first user through `POST /api/auth/setup`
  (403 once any user exists is accepted) and logs in; its credentials are in the
  secrets file. The email uses `example.com` because the backend's validator rejects
  `.invalid`.
- **`kubectl logs deploy/backend` shows only uvicorn's access lines.** The application
  logs (including `page_capture: wrote proxy limits to ConfigMap ...` and any
  `writing the proxy limits failed` traceback) go to the `system_logs` table through
  the DB log handler, not to stdout. Check the ConfigMap's content, the Logs page or
  `system_logs` in the lab's Postgres; the lab's `limits-check` watches the ConfigMap.
- **The API-server egress rule is generated per cluster.** `up` reads the
  `kubernetes` EndpointSlice and applies `backend-egress-apiserver` with the endpoint
  addresses (`$STATE/backend-egress-apiserver.yaml`); see Production deltas.
- The lab buckets are `lab-jobs`, `lab-results`, `lab-proxylog`, `lab-images` (the
  backend's) and `lab-e2e-results`, created by `up`. The host script `e2e` remains as
  the capture-only check; it uses its own results bucket because the live backend's
  ingest deletes any result, proxy log or job whose capture id it does not know.
- RustFS needs a writable `/logs` (it exits otherwise), so the lab gives it an
  `emptyDir` there; the rest of its root filesystem is read-only.

## Production deltas

- **Store.** Bring your own S3. The endpoint must be https; leave
  `CAPTURE_S3_INSECURE_HTTP` unset (the workloads refuse http without it). Put the
  non-secret settings in a ConfigMap named `capture-store` (the base reads the keys
  `CAPTURE_S3_ENDPOINT`, `CAPTURE_S3_BUCKET_JOBS`, `CAPTURE_S3_BUCKET_PROXYLOG`, and
  optionally `_REGION`, `_PATH_STYLE`, `_INSECURE_HTTP`). Buckets are provisioned by
  the operator; nothing here creates them.
- **Three scoped keys**, one Secret each (`CAPTURE_S3_ACCESS_KEY`/`_SECRET_KEY`):
    - backend: list/get/put/delete on its four prefixes (jobs, results, proxylog, images);
    - worker, `capture-store-worker`: list, get and delete on `jobs/` only (the delete
      is its claim on a job);
    - proxy, `capture-store-proxy`: put on `proxylog/` only.

  The proxy HMAC key is a fourth Secret, `capture-proxy-key` (`CAPTURE_PROXY_KEY`,
  proxy and backend only; the browser never receives it).
- **Store egress rule.** NetworkPolicy has no FQDN rules. In your overlay add an
  `ipBlock` egress rule for the S3 endpoint's addresses to the browser and proxy pods
  (this replaces the lab's `networkpolicy-store.yaml`). The proxy's own egress rule
  excludes private ranges, so a store on a private address needs it too.
- **Backend.** Secret `backend-env` with `DATABASE_URL` and `SECRET_KEY` (the backend
  refuses to boot with the default key); Secret `capture-store-backend`
  (`CAPTURE_S3_ACCESS_KEY`/`_SECRET_KEY`); the `capture-store` ConfigMap must also
  carry `CAPTURE_S3_BUCKET_RESULTS` and `CAPTURE_S3_BUCKET_IMAGES`. The Deployment
  sets `CAPTURE_LIMITS_SINK=configmap` and `CAPTURE_LIMITS_CONFIGMAP`
  (`capture-proxy-limits`, which must equal the Role's resourceName). `migrate` is an
  init container, the strategy is `Recreate` and there is one replica (APScheduler
  would fire twice). The image's user is not numeric, so the pod sets
  `runAsUser: 1000`. Ingress is yours to add (the base has no ingress rule); set
  `ALLOWED_ORIGINS` for your frontend origin. Set `CAPTURE_S3_PUBLIC_ENDPOINT` when
  the endpoint the worker uses (the one presigned URLs are signed for) differs from
  the backend's own path to the store.
- **RBAC.** The backend's Role is `get` + `patch` on the one ConfigMap
  `capture-proxy-limits`, nothing else. There is no `create`: `resourceNames` cannot
  restrict it, so the base pre-creates the ConfigMap empty. Re-applying the base is
  safe: a manifest with no `data` leaves the backend's key alone (checked with
  `kubectl apply`, client- and server-side). `verify` checks the Role by asking the
  API server what the ServiceAccount may do.
- **API-server egress.** The backend needs the API server to patch the ConfigMap.
  Write an `ipBlock` rule for the endpoint addresses and port from
  `kubectl get endpointslices -n default -l kubernetes.io/service-name=kubernetes`.
  Enforcement happens after DNAT, so the rule must name the endpoint, not the
  `kubernetes` Service ClusterIP: verified on kindnet, where a ClusterIP rule stayed
  closed and the endpoint rule was open. The addresses differ per cluster, so this
  rule is yours to generate (the lab script does).
- **Database and store egress.** The base's `backend-egress-world` allows everything
  except private ranges, plus DNS. Your overlay adds rules for the database and, if
  private, the store; the lab's `networkpolicy-backend.yaml` is the TEST ONLY example.
- **Limits file.** The proxy reads `CAPTURE_LIMITS_FILE=/capture_config/..data/proxy_limits.json`
  from the ConfigMap `capture-proxy-limits`, pre-created empty by the base; the
  backend writes the key `proxy_limits.json` (absent key means defaults). A ConfigMap volume file is a symlink and the proxy opens
  with `O_NOFOLLOW`, so the plain path is refused. `..data` is a symlinked
  *directory*, which is followed, and the final component is a regular file. An atomic
  ConfigMap update swaps `..data`, so the inode changes and the proxy re-reads.
  `subPath` would freeze the file. Checked in the lab: the symlink path reports
  `source=default`, the `..data` path `source=file`, and an update was picked up in
  16 to 66 s (kubelet sync; four updates measured).
- **One worker.** The browser Deployment is `replicas: 1` with `Recreate`
  (planning#323: a rolling update would briefly run two workers). Do not scale it.
- **Images.** The base leaves the image tag to the overlay; pin by digest in
  production.

## Restart back-off

Originally the worker captured ONE page and exited, so the kubelet restarted the
container after every capture, and the kubelet's crash-loop back-off applies even to a
clean exit 0 (10 s, doubling, capped at 5 min, reset after 10 min of running).
Measured in the lab, seconds from enqueue to `result.json`: a fresh pod took 3.0 s for
its first capture, but four jobs queued together took 73.6, 73.6, 158.3 and 320.7 s.
Docker's restart policy adds a growing delay too.

**Fix (planning#324):** the container's PID 1 is now `capture.supervisor`. It starts a
fresh worker process per capture, and after every worker exit kills every other
process in the container, reaps them and wipes `/tmp`, `/home/capture` and `/dev/shm`.
The kubelet sees one long-running container. A failing worker (non-zero exit) or a
failed wipe still ends the supervisor with exit 1, so genuine failures keep the
restart back-off. `shareProcessNamespace` must stay false (the supervisor refuses to
start unless it is PID 1).

With the supervisor, measured in the lab: a single capture took 2.0 to 3.0 s, and four
jobs queued together took 3.0, 5.0, 6.1 and 6.1 s (11 s wall time) with the container
restart count unchanged at 0.
