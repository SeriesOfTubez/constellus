# Page-capture spool contract (planning#280 S5b-2a, job v2 in S5b-2b, v3 in S5c-b1)

How the backend asks for a page capture and gets the results back, given one
hard rule: **the capture browser must never have a network route to the
backend.** (Decided on planning#280, comment 6451180624.)

It works like a CI runner with an artifact store. The worker in
`capture-browser` pulls a job and pushes artifacts. Nothing ever connects to
it, and it never connects to the backend. Jobs and artifacts go through a
store that both sides use and neither side serves. Today that store is a
shared volume. An S3-compatible backend (pre-signed per-capture URLs) is a
follow-up for K8s and cloud deployments.

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
6. Delete `claimed/<id>.json`.
7. **Exit.** One capture per process: compose restarts the container, so every
   capture starts with fresh tmpfs and a fresh process.

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
- Then delete `results/<id>/` and the proxy log.

A result whose `capture_id` is not a `queued` row is discarded (deleted, with
a warning logged).

A row still `queued` after the timeout becomes `failed` with
`failure_reason = 'timeout'`, and its job and claim files are removed.

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
