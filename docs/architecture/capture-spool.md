# Page-capture spool contract (planning#280 S5b-2a, job v2 in S5b-2b)

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

## Job v2 (backend → worker), at most 16 KiB

```json
{"v": 2, "capture_id": "<uuid>", "url": "https://example.com/",
 "viewport": {"width": 1280, "height": 800},
 "max_image_bytes": 2097152, "webp_qualities": [80, 60, 40],
 "user_agent_mode": "identifying",
 "user_agent": "ExampleScanner/1.0 (+https://scanner.example.test/about)"}
```

- `v` must be `2`. Every other value, including `1` and a boolean, is rejected.
- `user_agent_mode` is required and is `"stock"` or `"identifying"`. Anything
  else is rejected.
- `"identifying"` requires `user_agent`: a string of 1 to 256 characters, each
  in `0x20`..`0x7e` (printable ASCII). CR, LF, tab, other controls and
  non-ASCII are rejected.
- `"stock"` forbids `user_agent`: the key must be absent, even as `null`. A
  stock job that carries a UA means the two sides disagree, so the worker
  refuses it rather than guessing.
- `max_image_bytes` is at most 8 MiB.

The job and result versions are independent: the job is v2 and the result is
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
   - `v == 2`
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

- It does this only when the `capture_id` from `Proxy-Authorization` is a
  canonical UUID. Anything else is logged to stdout only.
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

### Residual risk, stated

If an attacker escapes both the Chromium renderer and its sandbox during one
capture, it holds the worker's write access to `/spool`. That lets it forge
the result of another capture that is still `queued`. It cannot:

- forge the proxy log (the browser never mounts that volume);
- reach the backend or the database;
- change the result of a capture that has already been ingested.

Capture rows are evidence that a person reads, never an authorisation.
