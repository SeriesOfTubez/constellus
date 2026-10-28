"""Pure helpers for the capture spool worker (planning#280 S5b-2a).

Contract: docs/architecture/capture-spool.md. Everything here is stdlib-only and
browser-free so it can be unit-tested without Playwright or Chromium.
"""

from __future__ import annotations

import json
import os
import shutil
import uuid
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

JOB_MAX_BYTES = 16 * 1024
RESULT_MAX_BYTES = 1024 * 1024
MAX_REQUESTS = 500
MAX_URL_CHARS = 2048
MAX_TEXT_CHARS = 1024
MAX_REDIRECTS = 50
MAX_SAN = 1000

# Bounds on what a job may ask for (the job is trusted-ish, but validated anyway).
MIN_VIEWPORT, MAX_VIEWPORT = 200, 4000
MAX_IMAGE_BYTES_LIMIT = 8 * 1024 * 1024
MAX_QUALITIES = 5

# Created under umask 007 by the worker. No chmod anywhere: the setgid bit comes
# from the pre-created 2770 parents (Linux inherits it on mkdir), so a new
# directory is group-owned by gid 10050 and the backend (same group) can delete it.
DIR_MODE = 0o770
FILE_MODE = 0o660
WORKER_UMASK = 0o007


class InvalidJob(Exception):
    """The job file is claimable but unusable; the worker reports `invalid_job`."""


def is_canonical_uuid(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 36:
        return False
    try:
        return str(uuid.UUID(value)) == value
    except ValueError:
        return False


def job_id_from_name(name: str) -> str | None:
    """`<canonical uuid>.json` -> the id, else None (never used as a path)."""
    if name.startswith(".") or not name.endswith(".json"):
        return None
    cid = name[: -len(".json")]
    return cid if is_canonical_uuid(cid) else None


def _int_in(value: object, lo: int, hi: int, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not lo <= value <= hi:
        raise InvalidJob(f"bad {what}")
    return value


def validate_job(raw: bytes, file_id: str) -> dict:
    """Parse + validate job bytes read from `claimed/<file_id>.json`."""
    if len(raw) > JOB_MAX_BYTES:
        raise InvalidJob("too large")
    try:
        job = json.loads(raw)
    except (ValueError, RecursionError):
        raise InvalidJob("not json") from None
    if not isinstance(job, dict):
        raise InvalidJob("not an object")
    if job.get("v") != 1 or isinstance(job.get("v"), bool):
        raise InvalidJob("bad version")
    if job.get("capture_id") != file_id:
        raise InvalidJob("capture_id does not match file name")
    url = job.get("url")
    if not isinstance(url, str) or not url or len(url) > MAX_URL_CHARS:
        raise InvalidJob("bad url")
    try:
        parts = urlsplit(url)
        host = parts.hostname
        parts.port  # noqa: B018 - raises ValueError on a bad port
    except ValueError:
        raise InvalidJob("bad url") from None
    if parts.scheme not in ("http", "https") or not host:
        raise InvalidJob("bad url scheme")
    vp = job.get("viewport")
    if not isinstance(vp, dict):
        raise InvalidJob("bad viewport")
    width = _int_in(vp.get("width"), MIN_VIEWPORT, MAX_VIEWPORT, "viewport")
    height = _int_in(vp.get("height"), MIN_VIEWPORT, MAX_VIEWPORT, "viewport")
    max_bytes = _int_in(job.get("max_image_bytes"), 1, MAX_IMAGE_BYTES_LIMIT, "max_image_bytes")
    qs = job.get("webp_qualities")
    if not isinstance(qs, list) or not 1 <= len(qs) <= MAX_QUALITIES:
        raise InvalidJob("bad webp_qualities")
    qualities = [_int_in(q, 1, 100, "webp quality") for q in qs]
    return {
        "capture_id": file_id,
        "url": url,
        "viewport": {"width": width, "height": height},
        "max_image_bytes": max_bytes,
        "webp_qualities": qualities,
    }


def pick_screenshot(
    take: Callable[[int], bytes], qualities: list[int], max_bytes: int
) -> tuple[bytes | None, int | None, str | None]:
    """Try `take(q)` for each quality in order; keep the first <= max_bytes.

    Returns (data, quality, omitted_reason). `take` raising stops the search with
    reason `error:<ExceptionClass>`; nothing fitting gives `over_cap`."""
    for q in qualities:
        try:
            data = take(q)
        except Exception as exc:  # noqa: BLE001 - recorded as the omitted reason
            return None, None, f"error:{type(exc).__name__}"
        if len(data) <= max_bytes:
            return data, q, None
    return None, None, "over_cap"


def _clip(value: Any, limit: int) -> Any:
    return value[:limit] if isinstance(value, str) else value


def _clean_cert(cert: Any) -> dict | None:
    if not isinstance(cert, dict):
        return None
    out = {k: _clip(cert.get(k), MAX_TEXT_CHARS) for k in ("subject", "issuer", "not_before", "not_after", "sha256")}
    san = cert.get("san_dns") or []
    out["san_dns"] = [_clip(s, 256) for s in list(san)[:MAX_SAN] if isinstance(s, str)]
    return out


def build_result(
    capture_id: str,
    *,
    captured: dict | None = None,
    requested_url: str | None = None,
    shot: tuple[bytes | None, int | None, str | None] = (None, None, None),
    user_agent: str | None = None,
    error: str | None = None,
) -> tuple[dict, bytes | None]:
    """Assemble result.json (v1) and apply every cap. Returns (result, image).

    `captured` is the dict from capture.run.capture_page (may be None when the
    job was invalid or the browser never ran)."""
    c = captured or {}
    data, quality, reason = shot
    err = error if error is not None else c.get("error")
    chain = [
        {"url": _clip(e.get("url"), MAX_URL_CHARS), "status": e.get("status")}
        for e in (c.get("redirect_chain") or [])[:MAX_REDIRECTS]
        if isinstance(e, dict)
    ]
    reqs_all = c.get("requests") or []
    reqs = [
        {
            "url": _clip(r.get("url"), MAX_URL_CHARS),
            "resource_type": _clip(r.get("resource_type"), 64),
            "failure": _clip(r.get("failure"), MAX_TEXT_CHARS),
            "is_navigation": bool(r.get("is_navigation")),
        }
        for r in reqs_all[:MAX_REQUESTS]
        if isinstance(r, dict)
    ]
    result: dict[str, Any] = {
        "v": 1,
        "capture_id": capture_id,
        "requested_url": _clip(requested_url if requested_url is not None else c.get("requested_url"), MAX_URL_CHARS),
        "final_url": _clip(c.get("final_url"), MAX_URL_CHARS),
        "status": c.get("status"),
        "redirect_chain": chain,
        "title": _clip(c.get("title"), MAX_TEXT_CHARS),
        "cert": _clean_cert(c.get("cert")),
        "requests": reqs,
        "screenshot": (
            {"file": "screenshot.webp", "bytes": len(data), "quality": quality}
            if data is not None
            else None
        ),
        "screenshot_omitted_reason": reason if data is None else None,
        "user_agent": _clip(user_agent, MAX_TEXT_CHARS),
        "error": _clip(err, MAX_TEXT_CHARS),
    }
    if len(reqs_all) > len(reqs):
        result["requests_truncated"] = True
    return cap_result(result), data if data is not None else None


def cap_result(result: dict) -> dict:
    """Shrink `requests` until the serialised result fits RESULT_MAX_BYTES."""
    def size() -> int:
        return len(json.dumps(result, separators=(",", ":")).encode())

    if size() <= RESULT_MAX_BYTES:
        return result
    result["requests_truncated"] = True
    reqs = result["requests"]
    while reqs and size() > RESULT_MAX_BYTES:
        del reqs[len(reqs) // 2 :]  # halve; terminates at empty
    return result


def serialise(result: dict) -> bytes:
    return json.dumps(result, separators=(",", ":")).encode()


def _write_file(path: str, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, FILE_MODE)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view) :]
    finally:
        os.close(fd)


def write_result(results_dir: str, capture_id: str, result: dict, image: bytes | None) -> str:
    """Write results/.<id>.tmp/ then rename to results/<id>/. Returns the final path."""
    if not is_canonical_uuid(capture_id):
        raise ValueError("capture_id is not a canonical uuid")
    tmp = os.path.join(results_dir, f".{capture_id}.tmp")
    final = os.path.join(results_dir, capture_id)
    shutil.rmtree(tmp, ignore_errors=True)  # leftover of a killed earlier attempt
    os.mkdir(tmp, DIR_MODE)
    _write_file(os.path.join(tmp, "result.json"), serialise(result))
    if image is not None:
        _write_file(os.path.join(tmp, "screenshot.webp"), image)
    os.rename(tmp, final)
    return final
