"""app.services.sec_edgar — the `data.sec.gov` client (planning#213, L4
slice 1).

A thin, defensive HTTP client for SEC EDGAR's structured submissions JSON.
`www.sec.gov` (the HTML/full-text-search surface) is never fetched by this
module or by anything in this slice — see `app.services.edgar_ingest`'s
module docstring for why.

## Testability — the injectable seams

Copied from `app.services.llm_connector`'s pattern (its module docstring's
"Testability" section) rather than inventing a second one: `_transport`
(an `httpx.BaseTransport | None`, used as `httpx.Client(transport=
_transport, ...)`), `_sleep` (defaults to `time.sleep`) and `_monotonic`
(defaults to `time.monotonic`, used for the rate limiter rather than
wall-clock `datetime.now`, since the rate limit is about elapsed intervals
between requests, not calendar time) are module-level so tests can
substitute `httpx.MockTransport` and control backoff/rate-limit timing
without ever touching the network. This module is registered in
`app/tests/conftest.py`'s `_GUARDED_MODULES` so a raw-assignment monkeypatch
of any of these (or of `_last_request_at`, reassigned wholesale rather than
mutated between requests) is restored between tests.

## Host allowlist — SSRF-shaped, not incidental

Every URL this module fetches is built from either a validated 10-digit CIK
(`^[0-9]{10}$`) or a validated `filings.files[].name`
(`^CIK[0-9]{10}-submissions-[0-9]{3}\\.json$`) taken from a response this
module already parsed — never any other string from a response body used to
build a URL. `_check_allowlisted` additionally re-checks the fully built URL
against `https://data.sec.gov/` before any I/O, so a future caller that
forgets the upstream validation still cannot be redirected anywhere else by
a crafted or corrupted value.

## Retry shapes — three real ones, not one

planning#213's research (2026-09-24 decisions comment) measured three
distinct transient shapes from SEC, and all three are retried the same way,
capped at 5 attempts with backoff `min(30, 2 * 2**i)` seconds:

  1. HTTP 429 or any 5xx status.
  2. `httpx.TimeoutException` / other `httpx.TransportError` (a real read
     timeout was observed against `www.sec.gov`, not just modelled).
  3. **HTTP 200 whose body fails `validate(body) -> bool`** — the
     research note's own example is a 200 with a short body reading "503
     Service Unavailable" as plain text, not JSON. A status check alone
     misses this shape entirely.

403 is never retried (raises `SecFetchError` with a hint to check
`SEC_USER_AGENT` — a wrong/missing User-Agent is the overwhelmingly likely
cause and retrying it burns 5 attempts for a guaranteed-repeat failure). 404
is never retried either (raises `SecNotFound` — the CIK does not exist;
retrying cannot fix that). This function never returns an empty or partial
result to its caller: every path either returns a validated `(bytes, str,
datetime, str)` tuple or raises.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from datetime import datetime, timezone
from typing import Callable
from urllib.parse import urlsplit

import httpx

from app.core.config import settings

log = logging.getLogger(__name__)

_ALLOWED_HOST = "data.sec.gov"
_ALLOWED_PREFIX = f"https://{_ALLOWED_HOST}/"

_CIK_RE = re.compile(r"^[0-9]{10}$")
_PAGE_NAME_RE = re.compile(r"^CIK[0-9]{10}-submissions-[0-9]{3}\.json$")

_MAX_ATTEMPTS = 5
# <= 8 req/s, comfortably under SEC's stated 10 req/s fair-access limit.
_MIN_REQUEST_INTERVAL_S = 0.125

_CONNECT_TIMEOUT_S = 10.0
_READ_TIMEOUT_S = 30.0

_PARALLEL_ARRAY_KEYS = ("form", "accessionNumber", "filingDate", "items")

# ── injectable seams (see module docstring's "Testability") ────────────────
_transport: httpx.BaseTransport | None = None
_sleep = time.sleep
_monotonic = time.monotonic

_rate_lock = threading.Lock()
_last_request_at: float | None = None


class SecFetchError(Exception):
    """Retries exhausted, or a non-retryable failure other than 403/404."""


class SecNotFound(Exception):
    """HTTP 404 — the CIK (or page) does not exist at SEC. Never retried."""


def _check_allowlisted(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.netloc != _ALLOWED_HOST:
        raise ValueError(
            f"URL not allowlisted (only https://{_ALLOWED_HOST}/ may be fetched by this module): {url!r}"
        )


def _headers() -> dict[str, str]:
    return {
        "User-Agent": settings.sec_user_agent or "",
        "Accept-Encoding": "gzip, deflate",
    }


def _backoff_seconds(attempt: int) -> float:
    """`attempt` is 1-based (the attempt that just failed). backoff =
    min(30, 2 * 2**i) with i = attempt - 1, so the sequence is 2, 4, 8, 16,
    capped at 30."""
    return min(30.0, 2 * 2 ** (attempt - 1))


def _retry_after_seconds(resp: httpx.Response) -> float | None:
    """An INTEGER `Retry-After` only — SEC has no reason to send the
    HTTP-date form for this endpoint, and parsing it is not asked for."""
    raw = resp.headers.get("Retry-After")
    if raw is None:
        return None
    try:
        return float(int(raw))
    except ValueError:
        return None


def _rate_limit() -> None:
    """Module-level lock plus last-request time, enforcing at least
    `_MIN_REQUEST_INTERVAL_S` between requests. Uses `_monotonic` (not
    wall-clock time) for the elapsed-interval math and `_sleep` for the
    wait, so a test can drive both without a real clock or a real delay."""
    global _last_request_at
    with _rate_lock:
        now = _monotonic()
        if _last_request_at is not None:
            remaining = _MIN_REQUEST_INTERVAL_S - (now - _last_request_at)
            if remaining > 0:
                _sleep(remaining)
                now = _last_request_at + _MIN_REQUEST_INTERVAL_S
        _last_request_at = now


def _validate_parallel_arrays(data: object) -> bool:
    if not isinstance(data, dict):
        return False
    if not all(isinstance(data.get(k), list) for k in _PARALLEL_ARRAY_KEYS):
        return False
    lengths = {len(data[k]) for k in _PARALLEL_ARRAY_KEYS}
    return len(lengths) == 1


def _validate_submissions_json(body: bytes) -> bool:
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return False
    if not isinstance(data, dict):
        return False
    if "cik" not in data or "name" not in data:
        return False
    recent = (data.get("filings") or {}).get("recent")
    return _validate_parallel_arrays(recent)


def _validate_page_json(body: bytes) -> bool:
    try:
        data = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return False
    return _validate_parallel_arrays(data)


def _fetch(url: str, *, validate: Callable[[bytes], bool]) -> tuple[bytes, str, datetime, str]:
    """The retryable core. Returns `(content, content_type, fetched_at,
    url)` on a validated 200, or raises `SecFetchError` / `SecNotFound`.
    Never returns an empty or partial result."""
    _check_allowlisted(url)

    last_error = "unknown error"
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        _rate_limit()
        try:
            with httpx.Client(
                transport=_transport,
                timeout=httpx.Timeout(
                    connect=_CONNECT_TIMEOUT_S, read=_READ_TIMEOUT_S, write=_READ_TIMEOUT_S, pool=_READ_TIMEOUT_S
                ),
            ) as client:
                resp = client.get(url, headers=_headers())
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            if attempt < _MAX_ATTEMPTS:
                _sleep(_backoff_seconds(attempt))
                continue
            raise SecFetchError(f"SEC EDGAR fetch of {url} failed after {attempt} attempts: {last_error}") from exc

        if resp.status_code == 403:
            raise SecFetchError(
                f"SEC EDGAR returned 403 for {url} — check that SEC_USER_AGENT is set to a "
                "descriptive, valid contact string (SEC fair-access policy)."
            )
        if resp.status_code == 404:
            raise SecNotFound(f"SEC EDGAR returned 404 for {url}")

        if resp.status_code == 429 or resp.status_code >= 500:
            last_error = f"HTTP {resp.status_code}"
            if attempt < _MAX_ATTEMPTS:
                delay = _retry_after_seconds(resp)
                if delay is None:
                    delay = _backoff_seconds(attempt)
                _sleep(delay)
                continue
            raise SecFetchError(f"SEC EDGAR fetch of {url} failed after {attempt} attempts: {last_error}")

        if resp.status_code == 200:
            if validate(resp.content):
                content_type = resp.headers.get("content-type", "")
                return resp.content, content_type, datetime.now(timezone.utc), url
            last_error = "200 response failed body validation"
            if attempt < _MAX_ATTEMPTS:
                _sleep(_backoff_seconds(attempt))
                continue
            raise SecFetchError(f"SEC EDGAR fetch of {url} failed after {attempt} attempts: {last_error}")

        # Any other status is not one of the documented transient shapes —
        # fail loud rather than silently retrying or swallowing it.
        raise SecFetchError(f"SEC EDGAR returned unexpected status {resp.status_code} for {url}")

    # Unreachable (the loop above always returns or raises), but keeps this
    # function's return type honest for a type checker.
    raise SecFetchError(f"SEC EDGAR fetch of {url} failed after {_MAX_ATTEMPTS} attempts: {last_error}")


def fetch_submissions(cik: str) -> tuple[bytes, str, datetime, str]:
    """Fetch `https://data.sec.gov/submissions/CIK##########.json` for a
    validated 10-digit `cik`. Validates that the parsed body is an object
    with `cik`, `name`, and a `filings.recent` whose `form`/
    `accessionNumber`/`filingDate`/`items` are equal-length lists."""
    if not isinstance(cik, str) or not _CIK_RE.match(cik):
        raise ValueError(f"fetch_submissions requires a 10-digit CIK string, got {cik!r}")
    url = f"{_ALLOWED_PREFIX}submissions/CIK{cik}.json"
    return _fetch(url, validate=_validate_submissions_json)


def fetch_submissions_page(name: str) -> tuple[bytes, str, datetime, str]:
    """Fetch one paged submissions file
    (`CIK##########-submissions-###.json`), `name` validated against the
    exact SEC naming pattern before any I/O. Validates that the parsed body
    is a top-level object with equal-length `form`/`accessionNumber`/
    `filingDate`/`items` arrays (the paged files are column-oriented like
    `filings.recent`, just without the wrapping `cik`/`name`/`filings`)."""
    if not isinstance(name, str) or not _PAGE_NAME_RE.match(name):
        raise ValueError(f"fetch_submissions_page requires a validated submissions page name, got {name!r}")
    url = f"{_ALLOWED_PREFIX}submissions/{name}"
    return _fetch(url, validate=_validate_page_json)
