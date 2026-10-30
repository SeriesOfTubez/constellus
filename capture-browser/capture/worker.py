"""capture-browser spool worker (planning#280 S5b-2a).

Pulls ONE job from the spool, runs one capture, pushes the artifacts and exits
(compose restarts the container, so every capture gets a fresh process and
tmpfs). It never connects to anything but capture-proxy. Contract:
docs/architecture/capture-spool.md.

    python -m capture.worker
"""

from __future__ import annotations

import os
import sys
import time

from capture import spool, store_s3

SPOOL_DIR = os.environ.get("CAPTURE_SPOOL_DIR", "/spool")
POLL_INTERVAL_S = 2.0


def check_dirs(root: str) -> tuple[str, str, str]:
    """The three subdirs are pre-created by the images (owner per image, group
    10050, 2770). Never create them here with a weaker mode: fail instead."""
    dirs = tuple(os.path.join(root, d) for d in ("jobs", "claimed", "results"))
    missing = [d for d in dirs if not os.path.isdir(d)]
    if missing:
        raise SystemExit(f"capture-worker: spool directories missing: {missing}")
    return dirs  # type: ignore[return-value]


def claim_next(jobs_dir: str, claimed_dir: str) -> str | None:
    """Claim the oldest job (uuidv7 sorts by time). Returns the capture id."""
    try:
        names = sorted(os.listdir(jobs_dir))
    except FileNotFoundError:
        return None
    for name in names:
        cid = spool.job_id_from_name(name)
        if cid is None:
            continue
        try:
            os.rename(os.path.join(jobs_dir, name), os.path.join(claimed_dir, name))
        except FileNotFoundError:
            continue  # another worker won
        return cid
    return None


def read_claimed(path: str) -> bytes:
    """Read at most JOB_MAX_BYTES+1 bytes; never follows a symlink."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        return os.read(fd, spool.JOB_MAX_BYTES + 1)
    finally:
        os.close(fd)


def process(cid: str, claimed_path: str, results_dir: str) -> None:
    try:
        raw = read_claimed(claimed_path)
    except OSError:
        raw = b""
    try:
        job = spool.validate_job(raw, cid)
    except spool.InvalidJob as exc:
        print(f"capture-worker: {cid}: invalid job: {exc}", file=sys.stderr, flush=True)
        result, image = spool.build_result(cid, error="invalid_job")
        spool.write_result(results_dir, cid, result, image)
        return

    result, image = _run_capture(cid, job)
    spool.write_result(results_dir, cid, result, image)


def _run_capture(cid: str, job: dict) -> tuple[dict, bytes | None]:
    # Imported here so `capture.spool` (and its tests) never need Playwright.
    from playwright.sync_api import sync_playwright

    from capture import run

    proxy_url = run.require_env()
    try:
        with sync_playwright() as p:
            captured, shot, ua = run.capture_page(
                p,
                cid,
                job["url"],
                proxy_url,
                job["proxy_token"],
                job["proxy_expires"],
                mode=job["mode"],
                viewport=job["viewport"],
                webp_qualities=job["webp_qualities"],
                max_image_bytes=job["max_image_bytes"],
                # None (stock mode) -> capture_page uses the browser's own UA.
                user_agent=job["user_agent"],
            )
        return spool.build_result(cid, captured=captured, shot=shot, user_agent=ua)
    except Exception as exc:  # noqa: BLE001 - the job must still get a result
        print(f"capture-worker: {cid}: capture failed: {exc!r}", file=sys.stderr, flush=True)
        return spool.build_result(
            cid, requested_url=job["url"], error=f"capture_failed:{type(exc).__name__}"
        )


def claim_next_s3(jobs) -> tuple[str, bytes] | None:
    """GET then DELETE: the delete is the claim. A failed delete = not ours; skip it."""
    for cid in jobs.list_ids():
        raw = jobs.get(cid)
        if raw is None:
            continue  # gone between list and get (ingested or swept)
        if not jobs.delete(cid):
            continue  # logged inside
        return cid, raw
    return None


def _upload_result(cid: str, store: dict, result: dict, image: bytes | None) -> bool:
    """Screenshot first, result.json LAST (it is the commit marker)."""
    if image is not None:
        try:
            store_s3.upload(store["screenshot_put"], image, "image/webp")
        except store_s3.UploadError as exc:
            print(f"capture-worker: {cid}: screenshot upload failed: {exc}", file=sys.stderr, flush=True)
            result = spool.cap_result(
                {**result, "screenshot": None, "screenshot_omitted_reason": "upload_failed"}
            )
    try:
        store_s3.upload(store["result_put"], spool.serialise(result), "application/json")
    except store_s3.UploadError as exc:
        print(f"capture-worker: {cid}: result upload failed: {exc}", file=sys.stderr, flush=True)
        return False
    return True


def process_s3(cid: str, raw: bytes, *, netloc: str, allow_http: bool) -> None:
    store = store_s3.extract_store(raw, netloc, allow_http)
    if store is None:
        print(
            f"capture-worker: {cid}: invalid store object; no result can be uploaded",
            file=sys.stderr,
            flush=True,
        )
        return
    try:
        job = spool.validate_job(raw, cid, store="s3", store_netloc=netloc, allow_http=allow_http)
    except spool.InvalidJob as exc:
        print(f"capture-worker: {cid}: invalid job: {exc}", file=sys.stderr, flush=True)
        result, _ = spool.build_result(cid, error="invalid_job")
        _upload_result(cid, store, result, None)
        return
    result, image = _run_capture(cid, job)
    _upload_result(cid, store, result, image)


def main() -> int:
    if not os.environ.get("CAPTURE_PROXY_URL"):
        raise SystemExit("CAPTURE_PROXY_URL is required")
    os.umask(spool.WORKER_UMASK)  # dedicated process: files 0660, dirs 0770, never world
    mode = os.environ.get("CAPTURE_STORE", "filesystem")
    if mode == "s3":
        return _main_s3()
    if mode != "filesystem":
        raise SystemExit("capture-worker: CAPTURE_STORE must be filesystem or s3")
    jobs_dir, claimed_dir, results_dir = check_dirs(SPOOL_DIR)
    while True:
        cid = claim_next(jobs_dir, claimed_dir)
        if cid is None:
            time.sleep(POLL_INTERVAL_S)
            continue
        claimed_path = os.path.join(claimed_dir, f"{cid}.json")
        process(cid, claimed_path, results_dir)
        try:
            os.unlink(claimed_path)
        except FileNotFoundError:
            pass
        return 0  # one capture per process; compose restarts the container


def _main_s3() -> int:
    try:
        cfg = store_s3.config_from_env()
    except store_s3.S3ConfigError as exc:
        raise SystemExit(f"capture-worker: {exc}") from None
    jobs = store_s3.S3Jobs(store_s3.make_client(cfg), cfg.bucket)
    last_error: str | None = None  # the listing error is printed once per change, not once per poll
    while True:
        try:
            claimed = claim_next_s3(jobs)
        except store_s3.StoreError as exc:
            if str(exc) != last_error:
                last_error = str(exc)
                print(f"capture-worker: listing jobs failed: {exc}", file=sys.stderr, flush=True)
            time.sleep(POLL_INTERVAL_S)
            continue
        last_error = None
        if claimed is None:
            time.sleep(POLL_INTERVAL_S)
            continue
        cid, raw = claimed
        process_s3(cid, raw, netloc=cfg.netloc, allow_http=cfg.allow_http)
        return 0  # one capture per process; compose restarts the container


if __name__ == "__main__":
    sys.exit(main())
