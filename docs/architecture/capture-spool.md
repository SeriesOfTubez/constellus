# Page-capture spool contract (planning#280 S5b-2a, job v2 in S5b-2b, v3 in S5c-b1; store backends in planning#318: S1a filesystem interface, S1b S3; S1c worker + proxy S3 modes)

How the backend asks for a page capture and gets the results back, given one
hard rule: **the capture browser must never have a network route to the
backend.** (Decided on planning#280, comment 6451180624.)

It works like a CI runner with an artifact store. The worker in
`capture-browser` pulls a job and pushes artifacts. Nothing ever connects to
it, and it never connects to the backend. Jobs and artifacts go through a
store that both sides use and neither side serves. Today that store is a
shared volume. An S3-compatible backend (pre-signed per-capture URLs) is
available for K8s and cloud deployments (planning#318 S1b, S1c). The S3 modes
exist and are selected by `CAPTURE_STORE=s3` on all three services.

## Volumes

| Volume | Mounted at | Who mounts it |
|---|---|---|
| `capture_spool` | `/spool` | backend (rw), capture-browser (rw) |
| `capture_proxylog` | `/proxylog` | backend (rw), capture-proxy (rw) |
| `capture_images` | `/captures` | backend only |

The browser never mounts `capture_proxylog`. So the proxy's record of each
request, including the **pinned IP** that the S5c cert signal relies on, is
something the browser cannot write or forge.

Permissions use a shared group: **gid 10050** (`capture-spool`), added to all
three services. Directories are `2770` (setgid, group-writable, no world
access), and whoever creates a directory sets that mode explicitly. Files are
created with mode `0660` or `0640`. Nothing in this contract is
world-writable.

## Identifiers

`capture_id` is the `page_captures.id` of the row: a **canonical lowercase
UUID string** (36 characters). Every component that turns a `capture_id` into
a path validates it first: `str(uuid.UUID(s)) == s`. A name that fails the
check is never used as a path.

Writers create temporary names that start with `.` and rename them into
place. Readers ignore any name that starts with `.`.

## Layout of `/spool`

```
/spool/jobs/<capture_id>.json      written by the backend
/spool/claimed/<capture_id>.json   moved here by the worker (atomic rename = claim)
/spool/results/<capture_id>/       written by the worker (atomic directory rename)
    result.json
    screenshot.webp                (only when a screenshot was kept)
```

### Layout on S3

Four buckets, each keyed under its own prefix:

```
jobs bucket      jobs/<capture_id>.json
results bucket   results/<capture_id>/result.json
                 results/<capture_id>/screenshot.webp
proxylog bucket  proxylog/<capture_id>.jsonl
images bucket    images/<capture_id>.webp
```

All four variables may name one bucket: keys are disjoint by prefix.

## Job v3 (backend → worker), at most 16 KiB

```json
{"v": 3, "capture_id": "<uuid>", "url": "https://example.com/",
 "mode": "live", "proxy_token": "<64 lowercase hex>",
 "proxy_expires": 1900000000,
 "viewport": {"width": 1280, "height": 800},
 "max_image_bytes": 2097152, "webp_qualities": [80, 60, 40],
 "user_agent_mode": "identifying",
 "user_agent": "ExampleScanner/1.0 (+https://scanner.example.test/about)"}
```

- `v` must be `3`. Every other value, including `1`, `2` and a boolean, is rejected.
- `mode` is required and is exactly `"live"` or `"archive"`.
- `proxy_token` is required: a string that fully matches `[0-9a-f]{64}` (see
  "Proxy credential" below).
- `proxy_expires` is required: an integer (not a boolean) with
  `1 <= x < 10**12`, unix seconds. The browser does not compare it with the
  clock; the proxy does.
- In `"archive"` mode the `url` must also be `https`, with a host that is
  exactly in `ARCHIVE_HOSTS` (`web.archive.org`), port absent or `443`, no
  userinfo, and a Wayback playback path, `/web/<digits>…` (never `/save/` or any other endpoint). Anything else is rejected.
- `user_agent_mode` is required and is `"stock"` or `"identifying"`. Anything
  else is rejected.
- `"identifying"` requires `user_agent`: a string of 1 to 256 characters, each
  in `0x20`..`0x7e` (printable ASCII). CR, LF, tab, other controls and
  non-ASCII are rejected.
- `"stock"` forbids `user_agent`: the key must be absent, even as `null`. A
  stock job that carries a UA means the two sides disagree, so the worker
  refuses it rather than guessing.
- `max_image_bytes` is at most 8 MiB.

The job and result versions are independent: the job is v3 and the result is
v1. The backend records `user_agent_mode` and `image_max_bytes` on the
`page_captures` row (migration 0092), and the ingest enforces the row's cap.

The backend writes `jobs/.<id>.tmp` and renames it to `jobs/<id>.json`. It
does this only AFTER the `page_captures` row (status `queued`) has been
committed.

### The optional `store` object (S3 mode only)

When `CAPTURE_STORE=s3` the job also carries
`"store": {"result_put": "<presigned PUT URL>", "screenshot_put": "<presigned PUT URL>", "expires": <int>}`.
It is present only in S3 mode, so today's filesystem worker never sees it (it
reads known keys only). The worker requires it in S3 mode and refuses a
filesystem-mode job that carries it. Each URL must be `https` (`http` only with `CAPTURE_S3_INSECURE_HTTP=1`), at most 4096 characters, carry no credentials, and point at the host of the worker's own `CAPTURE_S3_ENDPOINT` (or at a bucket's virtual-hosted subdomain of it). `expires` follows the `proxy_expires` rule and is the proxy credential's `exp`: the URLs expire with the job's credential. A job whose `store` object is invalid gets no result at all (the worker logs it and the row times out), because there is nowhere to upload one.

## Worker loop (capture-browser)

1. List `jobs/*.json` and sort by name. A uuidv7 sorts by creation time.
2. Claim a job with `rename(jobs/<id>.json, claimed/<id>.json)`. If that
   raises `FileNotFoundError`, another worker won, so move on to the next job.
3. Validate the job:
   - `v == 3`
   - `mode`, `proxy_token`, `proxy_expires` and (in archive mode) the archive URL rules
   - `user_agent_mode` and `user_agent` follow the job rules above
   - `capture_id` equals the file name
   - the URL scheme is `http` or `https`
   - the job is no larger than its size cap

   An invalid job still gets a result, with `error: "invalid_job"`.
4. Run ONE capture: one navigation, as `capture.run` does. Take the
   screenshot with CDP `Page.captureScreenshot {format: "webp", quality: q}`
   for each `q` in `webp_qualities`, and keep the first one that is at most
   `max_image_bytes`. If none fits, keep no image and set
   `screenshot_omitted_reason: "over_cap"`.
5. Write `results/.<id>.tmp/` (`result.json` plus any `screenshot.webp`), then
   rename it to `results/<id>/`.
   **S3 variant (S1c):** PUT `screenshot.webp` through its presigned URL first,
   then `result.json`. `result.json` is the commit marker.
6. Delete `claimed/<id>.json`.
7. **Exit.** One capture per process. The container's PID 1 is
   `capture.supervisor`: after each worker exit it kills every other process in
   the container, reaps them, wipes `/tmp`, `/home/capture` and `/dev/shm`, and
   starts a fresh worker, so every capture gets a fresh process and empty scratch
   space without a container restart (which Kubernetes back-off would delay). A
   non-zero worker exit or a failed wipe makes the supervisor exit 1, and the
   restart policy takes over.

**On S3 (`CAPTURE_STORE=s3`):** the worker holds a key with list, get and delete on the jobs bucket and nothing else; it requires an explicit `CAPTURE_S3_ENDPOINT` and never a spool volume.

That key can read every queued job (each carries a proxy token and presigned PUT URLs), so the worker drops every `CAPTURE_S3_*` variable from its environment right after reading its configuration, before Playwright starts, and marks itself non-dumpable (`prctl(PR_SET_DUMPABLE, 0)`, both modes; it refuses to start if that fails on Linux) so Chromium, which runs as the same uid, cannot read `/proc/<pid>/environ` or ptrace it. Chromium itself is launched with an allowlisted environment (`capture/browser_env.py`), not the worker's.

1. List `jobs/` and sort by name.
2. GET the job, then DELETE it. **The delete is the claim.** A delete that fails means the job is not ours: log it and move on; the backend's delete on ingest or on timeout is the backstop. A crash after the delete leaves no retry, like a crashed filesystem worker's `claimed/` file: the row times out. There is no `claimed/` on S3 and there is one worker (several workers: planning#323).
3. Validate as above, plus the `store` object. An invalid job still gets its `invalid_job` result through `store.result_put`.
4. Run ONE capture, as above.
5. PUT `screenshot.webp` through `store.screenshot_put` first, then `result.json` through `store.result_put`: `result.json` is the commit marker. The PUTs are plain HTTP with `Content-Type` and `Content-Length` only (no `x-amz-*` headers), never through the capture proxy, with redirects refused. If the screenshot PUT fails the result is still uploaded, with `screenshot: null` and `screenshot_omitted_reason: "upload_failed"`. If the result PUT fails nothing more is tried: the row times out.
6. Exit, as above.

When there is no job, the worker sleeps and polls again. It does not exit
while idle.

## `result.json` v1, at most 1 MiB

```json
{"v": 1, "capture_id": "<uuid>", "requested_url": "...", "final_url": "...",
 "status": 200, "redirect_chain": [{"url": "...", "status": 301}],
 "title": "...", "cert": {"subject": "...", "issuer": "...", "not_before": "...",
 "not_after": "...", "san_dns": ["..."], "sha256": "..."},
 "requests": [{"url": "...", "resource_type": "...", "failure": null, "is_navigation": true}],
 "screenshot": {"file": "screenshot.webp", "bytes": 12345, "quality": 80},
 "screenshot_omitted_reason": null, "user_agent": "...", "error": null}
```

- `cert` is `null` when the page was not served over TLS.
- `screenshot` is `null` when no image was kept.
- `requests` holds at most 500 entries.

## Proxy log (`capture-proxy` → backend)

When `CAPTURE_PROXY_LOG_DIR` is set, the proxy appends each request record (the
same JSON object it prints to stdout) to `<dir>/<capture_id>.jsonl`.

- The `capture_id` and `mode` come from the per-job credential in
  `Proxy-Authorization`, and are trusted only after the token has verified.
  It writes the file only when that `capture_id` is a canonical UUID. Anything
  else is logged to stdout only.
- The file is opened with `O_WRONLY|O_APPEND|O_CREAT|O_NOFOLLOW` and mode
  `0660`.
- Each file is capped at 4 MiB. Past the cap, the proxy logs to stdout only.

Stdout logging is unchanged.

**On S3 (`CAPTURE_STORE=s3`):** the proxy holds a put-only key on the proxylog bucket (`CAPTURE_S3_BUCKET_PROXYLOG`); `CAPTURE_PROXY_LOG_DIR` must be unset. S3 has no append, so the proxy buffers each capture's records in memory and PUTs the whole `proxylog/<capture_id>.jsonl` object, replacing the previous one, about 1 s after the last record, at once when the 4 MiB cap is reached, and on shutdown. A buffer is dropped once it has been idle for the credential's maximum lifetime (3900 s). At most 16 captures are buffered at a time; past that, and past the cap, records go to stdout only. A failed PUT is logged by its error code and retried at the next record or at shutdown; the proxy never fails a connection because the store misbehaves. The backend's 5 s result min-age is what gives the proxy its time to flush: the browser closes its connections, which produces the last records, before the worker uploads `result.json`. A log that still arrives late is lost without a trace today (planning#325 records that on the row).

## Ingest (backend)

A scheduler tick runs over `results/<id>/` directories that are at least 5
seconds old. The age gives the proxy time to flush its log lines when
connections close.

**Everything under `/spool` is untrusted input.** The browser that wrote it
rendered an arbitrary page.

- `lstat` every entry and refuse symlinks and anything that is not a regular
  file or directory.
- Read fixed names only.
- Enforce the size caps above.
- Parse JSON only.
- Accept a screenshot only if it starts with `RIFF` and has `WEBP` at offset
  8. **Never decode the image.**
- Copy the screenshot to `/captures/<id>.webp`.
- Read `/proxylog/<id>.jsonl`.
- Then delete `results/<id>/`, the proxy log and the job (`jobs/<id>.json`). On the
  filesystem the worker already removed its claim; on S3 the worker already deleted the job when it claimed it, so this
  delete is the backstop.

On S3 a result is visible only once `results/<id>/result.json` exists (the
commit marker); its LastModified is the result's time. A `result.json` whose
claimed screenshot never arrived ends `invalid_image`.

A result whose `capture_id` is not a `queued` row is discarded (deleted, with
a warning logged).

A row still `queued` after the timeout becomes `failed` with
`failure_reason = 'timeout'`, and its job, any result under its id and its proxy log are removed (on S3 this clears an orphan screenshot).

## Proxy credential

The browser authenticates to capture-proxy with a per-job credential, not a
shared secret.

- **Key:** `CAPTURE_PROXY_KEY`, stripped of whitespace, valid only if it is at
  least 32 characters. Only the backend and capture-proxy hold it;
  capture-browser never receives it. The backend refuses to queue a capture
  without it (`capture:not_configured`, no row written).
- **Modes:** `("live", "archive")`, exact strings.
- **Expiry `exp`:** integer unix seconds, wire form plain ASCII digits with no
  sign and no leading zero, 1 to 12 digits (`[1-9][0-9]{0,11}`). The backend
  mints `exp = now + queue_timeout_seconds + CREDENTIAL_RUN_MARGIN_S` (margin
  300 s). The proxy accepts a credential only if
  `now <= exp <= now + MAX_CREDENTIAL_TTL_S` (3900 = `QUEUE_TIMEOUT_MAX` 3600
  + 300; a backend drift test asserts the sum). The check runs per new
  connection; an established tunnel is not cut at `exp`.
- **Token:** `HMAC-SHA256(key, "v3|<capture_id>|<mode>|<exp>")` as 64
  lowercase hex characters. `capture_id` must be a canonical lowercase UUID.
- **Header:** `Proxy-Authorization: Basic base64("<capture_id>|<mode>|<exp>:<token>")`.
  The username is `<capture_id>|<mode>|<exp>` and must split on `|` into
  exactly three parts; the password is the token. The backend writes the token
  and `proxy_expires` into the job; the worker passes them to Chromium's proxy
  setting.
- **Proxy check:** the proxy re-derives the token for the claimed
  `capture_id`, `mode` and `exp` and compares in constant time, then checks the
  time window. A malformed, expired or too-far-future `exp` fails exactly like
  a bad MAC: 407, log reason `auth`.
- **Archive policy:** an archive-mode request is allowed only as `CONNECT` to
  port 443 with a host that is exactly in `ARCHIVE_HOSTS`
  (`web.archive.org`): no trailing-dot stripping, no suffix match, never an IP
  literal. Otherwise the proxy answers 403 with reason `archive_host`. Live
  mode keeps its existing policy. The browser also aborts non-archive requests
  in archive mode, and its `archive_request_allowed` additionally requires the
  path to be a playback path, `/web/<digits>…`. That path check is the only layer that can see
  paths (the proxy sees opaque TLS); it is what stops page JS requesting Save
  Page Now (`/save/...`) on `web.archive.org`. The host check is the proxy's.
- **Drift:** `ARCHIVE_HOSTS`, `MODES` and `JOB_VERSION` are plain literals
  kept identical in `capture-proxy/proxy.py`, `capture-browser/capture/spool.py`
  and the backend, and a test compares them by `ast`.
- **Rotation:** changing the key invalidates every queued job, which then fails
  proxy authentication.
- **Test vectors** (key = 32 times `k`, capture_id
  `00000000-0000-4000-8000-000000000001`, exp `2000000000`):
  - live: `fd4cc753d722f5681637818178f5319706eb2b66b6c19cc182666f4d6e9e1382`
  - archive: `ec9eb6417283118f7de8b8013f57c6b86582311497a3921e31bca75ca696ea9a`

### Residual risk, stated

Per-job tokens close impersonation: a compromised browser cannot present a
`capture_id` or `mode` it was not given, because it cannot compute a token for
them (it never holds the key).

What remains: if an attacker escapes both the Chromium renderer and its
sandbox during one capture, it holds the worker's read/write access to
`/spool`. It can read another job's token and use it, within that job's mode,
only until that token's `exp`; it can also forge the result of that capture.
A failed job's token stays valid until its `exp`: there is no revocation. It
cannot:

- forge the proxy log (the browser never mounts that volume);
- reach the backend or the database;
- change the result of a capture that has already been ingested.

The proxy cannot see paths inside TLS, so the Save-Page-Now guard is the
browser's route layer, which page JS cannot reach without escaping the
sandbox. Playwright does not route WebSockets, but the proxy still enforces the
host policy on their CONNECT.

Capture rows are evidence that a person reads, never an authorisation.

## Proxy limits

The proxy has no database and no route to the backend, so its tunable limits
travel through a volume: `capture_config`, mounted read-write on the backend at
`/capture_config` and read-only on capture-proxy.

- **File:** `/capture_config/proxy_limits.json`, one line of canonical JSON
  (sorted keys, no spaces): `{"connect_timeout_s":10,"idle_timeout_s":30,"max_connections":256,"version":1}`.
- **Writer:** the backend's `page_capture.tick()`, as its first step every
  pass. It rewrites the file whenever its content differs from the current
  settings (`capture.proxy_connect_timeout_seconds`,
  `capture.proxy_idle_timeout_seconds`, `capture.proxy_max_connections`), so a
  fresh volume or a restart heals itself. The settings PUT does not write it.
  The write is a temp file plus rename; a symlink at the target is replaced, not
  followed, and a config directory that is a symlink is refused.
- **Reader:** the proxy checks `(st_ino, st_mtime_ns, st_size)` of the file on
  each new connection and re-reads it only when that key changes.
- **Clamping:** the proxy clamps every value to its own bounds (connect 1-60 s,
  idle 5-600 s, connections 1-1024). A missing, oversize (over 4096 bytes),
  malformed or wrong-version file means the defaults (10 s, 30 s, 256).
- **In flight:** connections already open keep the limits they started with.
- **Guards are not settings.** `ALLOWED_PORTS`, the address blocklist, proxy
  authentication and resolve-once pinning are constants and are never read from
  this file or from any setting.
- **On Kubernetes** the file travels as a ConfigMap written by the backend (planning#324, with the store NetworkPolicy and a local kind lab). A ConfigMap volume's file is a symlink, which the proxy's `O_NOFOLLOW` open refuses, so `CAPTURE_LIMITS_FILE` must point at `..data/proxy_limits.json` or the mount must use a `subPath`.

## Store interface (planning#318)

The backend reaches the spool, the proxy log and the stored images only through
`backend/app/services/capture_store.py`. Callers pass capture ids and names,
never paths; file names are built inside the store. `FilesystemStore` is the
Compose backend and keeps the filesystem-only defences (lstat, no symlinks,
`O_NOFOLLOW`/`O_NONBLOCK`, fstat re-check, regular files only). Content checks
(JSON parse, WebP magic, sha256, field validation) stay in `page_capture.py`, so
every backend shares them. The proxy limits file is not part of the store. A
guard test keeps `page_capture.py` free of direct file access.

### S3 backend (planning#318 S1b)

`backend/app/services/capture_store_s3.py`, selected by `CAPTURE_STORE=s3`.

| Variable | Meaning |
|---|---|
| `CAPTURE_STORE` | `filesystem` (default) or `s3`. Anything else is an error. |
| `CAPTURE_S3_ENDPOINT` | Endpoint URL; unset means AWS default endpoints. |
| `CAPTURE_S3_PUBLIC_ENDPOINT` | The endpoint the presigned URLs are signed for, when the worker reaches the store by a different host than the backend (unset = `CAPTURE_S3_ENDPOINT`). Same scheme rules. |
| `CAPTURE_S3_REGION` | Region, default `us-east-1`. |
| `CAPTURE_S3_ACCESS_KEY` / `CAPTURE_S3_SECRET_KEY` | Both or neither; neither means botocore's default credential chain. |
| `CAPTURE_S3_PATH_STYLE` | `true` (default) or `false`. |
| `CAPTURE_S3_INSECURE_HTTP` | `1` allows an `http` endpoint. Test profile only. |
| `CAPTURE_S3_BUCKET_JOBS` / `_RESULTS` / `_PROXYLOG` / `_IMAGES` | The four bucket names. |

Worker and proxy (S1c):

- `CAPTURE_STORE=s3` selects the mode in both. Any other `CAPTURE_STORE` value stops the process.
- Both take `CAPTURE_S3_ENDPOINT` (required, their own path to the store), `CAPTURE_S3_REGION`, `CAPTURE_S3_ACCESS_KEY`/`_SECRET_KEY` (both or neither), `CAPTURE_S3_PATH_STYLE` and `CAPTURE_S3_INSECURE_HTTP`.
- The worker takes `CAPTURE_S3_BUCKET_JOBS` only; the proxy takes `CAPTURE_S3_BUCKET_PROXYLOG` only.
- `CAPTURE_SPOOL_DIR` is unused, and `CAPTURE_PROXY_LOG_DIR` must be unset, in S3 mode.

- **Fail closed.** An unknown backend or an incomplete S3 environment makes the
  capture store unavailable (`spool_unavailable`). There is no fallback to the
  filesystem.
- **Libraries.** botocore only (no boto3), with SigV4 presigning.
- **Read-side caps.** The ContentLength is compared with the cap and at most
  cap+1 bytes are read. A presigned PUT cannot bound the size of an upload, so
  the read side is the guarantee.
- **Errors.** Every store error surfaces as an `OSError`, so the callers'
  fail-closed handlers apply. Error text carries the error code only, never a
  key, secret or URL.
- **Buckets.** The backend never creates buckets; the operator provisions them.
- **Transport.** https is required unless `CAPTURE_S3_INSECURE_HTTP=1`, which
  is for the test profile only.
- **IAM shape.** Backend: list/get/put/delete on its four prefixes. Worker: list, get and delete on the jobs bucket (the delete is its claim). Proxy: put on the proxylog bucket. Nobody but the backend reads results or images. Users never receive store URLs; the backend streams images.
- **RustFS test profile.** The `capture-s3-test` compose profile runs RustFS,
  pinned by digest, for the S3 conformance tests (and a CI job) only. It is
  never a production default and is never exposed beyond `127.0.0.1`: the
  console is off, data is a tmpfs, and its root credentials come from `.env`
  with no default. The pin matters because of RustFS's pre-1.0 CVE trail and
  the 1.0.0/1.0.1 advisories fixed in 1.0.2.

Not part of the store by design: the proxy-limits file. On Kubernetes it is a ConfigMap written by the backend (planning#324). Compose keeps the filesystem spool; the browser and proxy join the store network only on Kubernetes or in an ad-hoc end-to-end run.
