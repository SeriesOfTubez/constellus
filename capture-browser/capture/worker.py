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

from capture import spool

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

    # Imported here so `capture.spool` (and its tests) never need Playwright.
    from playwright.sync_api import sync_playwright

    from capture import run

    proxy_url, token = run.require_env()
    try:
        with sync_playwright() as p:
            captured, shot, ua = run.capture_page(
                p,
                cid,
                job["url"],
                proxy_url,
                token,
                viewport=job["viewport"],
                webp_qualities=job["webp_qualities"],
                max_image_bytes=job["max_image_bytes"],
            )
        result, image = spool.build_result(cid, captured=captured, shot=shot, user_agent=ua)
    except Exception as exc:  # noqa: BLE001 - the job must still get a result
        print(f"capture-worker: {cid}: capture failed: {exc!r}", file=sys.stderr, flush=True)
        result, image = spool.build_result(
            cid, requested_url=job["url"], error=f"capture_failed:{type(exc).__name__}"
        )
    spool.write_result(results_dir, cid, result, image)


def main() -> int:
    run_env_ok = os.environ.get("CAPTURE_PROXY_URL") and os.environ.get("CAPTURE_PROXY_TOKEN")
    if not run_env_ok:
        raise SystemExit("CAPTURE_PROXY_URL and CAPTURE_PROXY_TOKEN are required")
    os.umask(spool.WORKER_UMASK)  # dedicated process: files 0660, dirs 0770, never world
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


if __name__ == "__main__":
    sys.exit(main())
