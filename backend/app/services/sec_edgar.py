"""app.services.sec_edgar — the SEC EDGAR HTTP client (planning#213, L4
slices 1 and 2).

A thin, defensive HTTP client for two SEC EDGAR hosts: `data.sec.gov` (the
structured submissions JSON, slice 1) and `www.sec.gov` (the HTML filing
index and the filing documents it lists — EX-21 exhibits and primary 10-K
bodies, slice 2). Widened from `data.sec.gov`-only per planning#213's
2026-09-25 decisions comment: a probe of `www.sec.gov` that slice 1 found
timing out with a real 503 answered normally (~0.3s) a day later — both
transient shapes are still handled by the same retry loop below, since
either can recur.

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

Every URL this module fetches is built from validated parts only, never any
string taken verbatim from a response body:

  - `data.sec.gov`: a validated 10-digit CIK (`^[0-9]{10}$`) or a validated
    `filings.files[].name` (`^CIK[0-9]{10}-submissions-[0-9]{3}\\.json$`).
  - `www.sec.gov`: `filing_index_url`/`filing_document_url` build from a
    validated 10-digit CIK, a validated accession number (the same
    `^[0-9]{10}-[0-9]{2}-[0-9]{6}$` shape as migration 0062's CHECK — this
    module never imports it from `app.services.edgar_ingest`, the same
    "a migration/module must keep working even if the other renames its
    constant" reasoning 0062's own docstring gives for not importing
    either), and, for a filing document, a validated filename
    (`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` — no `/`, so no directory
    traversal is representable at all, and a leading-alnum requirement
    additionally rules out a bare `..`). **This module never follows an
    `href` from a fetched response into a new URL.**

`_check_allowlisted` re-checks the fully built URL against the allowlist
before any I/O: `https` scheme and host in `{data.sec.gov, www.sec.gov}`,
and, for `www.sec.gov` specifically, a path that starts with
`/Archives/edgar/data/` (the only tree this module ever needs there —
`www.sec.gov` also serves full-text search, EDGAR's own UI, and other
surfaces this slice has no business fetching). So a future caller that
forgets the upstream validation still cannot be redirected anywhere else,
or to another part of `www.sec.gov`, by a crafted or corrupted value.

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
retrying cannot fix that). An oversize 200 body (over the 10 MiB evidence
cap) is likewise never retried — raises `SecDocumentTooLarge`, a
`SecFetchError` subclass, and is never truncated (slice 2; see that
exception's own docstring). This function never returns an empty or
partial result to its caller: every path either returns a validated
`(bytes, str, datetime, str)` tuple or raises.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Callable
from urllib.parse import urlsplit

import httpx

from app.core.config import settings

log = logging.getLogger(__name__)

_DATA_HOST = "data.sec.gov"
_WWW_HOST = "www.sec.gov"
_ALLOWED_HOSTS = frozenset({_DATA_HOST, _WWW_HOST})
_ALLOWED_PREFIX = f"https://{_DATA_HOST}/"
# The only tree this module ever fetches on www.sec.gov — see module
# docstring's "Host allowlist" section.
_WWW_REQUIRED_PATH_PREFIX = "/Archives/edgar/data/"

_CIK_RE = re.compile(r"^[0-9]{10}$")
_PAGE_NAME_RE = re.compile(r"^CIK[0-9]{10}-submissions-[0-9]{3}\.json$")
# Same shape as migration 0062's `ck_entity_filing_events_accession` CHECK
# and 0063's two CHECKs — duplicated literally, not imported (see module
# docstring).
_ACCESSION_RE = re.compile(r"^[0-9]{10}-[0-9]{2}-[0-9]{6}$")
# No `/`, so no directory traversal is representable; a leading-alnum
# requirement also rules out a bare `..` on its own.
_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

_MAX_ATTEMPTS = 5
# <= 8 req/s, comfortably under SEC's stated 10 req/s fair-access limit.
_MIN_REQUEST_INTERVAL_S = 0.125

_CONNECT_TIMEOUT_S = 10.0
_READ_TIMEOUT_S = 30.0

_PARALLEL_ARRAY_KEYS = ("form", "accessionNumber", "filingDate", "items")

# migration 0061's `ck_evidence_blobs_byte_length` (10 MiB) is the real cap
# `entity_graph.store_evidence` will accept — duplicated here as a literal
# rather than imported (no existing Python constant exists for it; the
# CHECK is SQL text in the migration file, not an importable value) so this
# module can refuse an oversize document BEFORE spending a store_evidence
# round trip on bytes the database would reject anyway.
_MAX_EVIDENCE_BYTES = 10_485_760

# SEC error-page markers (research note): a 200 whose SHORT body is plain
# text reading one of these, not the document at all.
_ERROR_PAGE_MARKERS = (
    b"Request Rate Threshold Exceeded",
    b"Undeclared Automated Tool",
    b"503 Service Unavailable",
)
_ERROR_MARKER_BODY_LIMIT = 4096

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


class SecDocumentTooLarge(SecFetchError):
    """A 200 response body exceeds `_MAX_EVIDENCE_BYTES`. Never retried —
    the document is not going to shrink — and never truncated: the caller
    (`app.services.edgar_ingest`) counts this document as `oversize_skipped`
    and moves on to the next one; `entity_graph.store_evidence` is never
    called for these bytes, so the evidence hash-of-fetched-bytes invariant
    is never in question for a body this module never returns."""


def _check_allowlisted(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme != "https" or parts.netloc not in _ALLOWED_HOSTS:
        raise ValueError(
            f"URL not allowlisted (only https://{{{','.join(sorted(_ALLOWED_HOSTS))}}}/ "
            f"may be fetched by this module): {url!r}"
        )
    if parts.netloc == _WWW_HOST and not parts.path.startswith(_WWW_REQUIRED_PATH_PREFIX):
        raise ValueError(
            f"URL not allowlisted (www.sec.gov paths must start with "
            f"{_WWW_REQUIRED_PATH_PREFIX!r}): {url!r}"
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
            if len(resp.content) > _MAX_EVIDENCE_BYTES:
                # Permanent, not transient: retrying cannot shrink the
                # document. Raise immediately, matching 403/404's
                # never-retried treatment, and BEFORE `validate` so a huge
                # body is never scanned for the short-body error markers
                # (moot anyway — `_validate_filing_document` only checks
                # bodies under `_ERROR_MARKER_BODY_LIMIT`).
                raise SecDocumentTooLarge(
                    f"SEC EDGAR document at {url} is {len(resp.content)} bytes, "
                    f"over the {_MAX_EVIDENCE_BYTES}-byte evidence cap (migration 0061's "
                    "ck_evidence_blobs_byte_length) — skipped, never truncated."
                )
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


# ── www.sec.gov — the filing index and its documents (slice 2) ─────────────


def filing_index_url(cik10: str, accession: str) -> str:
    """Builds `https://www.sec.gov/Archives/edgar/data/{cik}/{accession_no
    dash}/{accession}-index.htm`, from a validated 10-digit `cik10` and a
    validated accession number ONLY. The path CIK is UNPADDED (`int()`) —
    that is how EDGAR's own directory layout spells it, unlike the
    zero-padded `CIK##########` form `data.sec.gov` uses. Raises
    `ValueError` (zero I/O) on anything that fails validation."""
    if not isinstance(cik10, str) or not _CIK_RE.match(cik10):
        raise ValueError(f"filing_index_url requires a 10-digit CIK string, got {cik10!r}")
    if not isinstance(accession, str) or not _ACCESSION_RE.match(accession):
        raise ValueError(f"filing_index_url requires a validated accession number, got {accession!r}")
    accession_nodash = accession.replace("-", "")
    return f"https://{_WWW_HOST}{_WWW_REQUIRED_PATH_PREFIX}{int(cik10)}/{accession_nodash}/{accession}-index.htm"


def is_valid_filename(filename: object) -> bool:
    """The same check `filing_document_url` enforces, for callers that
    want to skip a bad filename rather than catch a ValueError."""
    return isinstance(filename, str) and bool(_FILENAME_RE.match(filename))


def filing_document_url(cik10: str, accession: str, filename: str) -> str:
    """Same directory as `filing_index_url`, plus a validated `filename`
    (`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` — no slash, so no path traversal
    is representable). **Never** call this with a filename taken verbatim
    from a fetched response's `href` — only with a `Document`/
    `primaryDocument` value this module's caller has already run through
    this same check (this function IS that check, so calling it is
    sufficient, but the caller must not skip calling it by constructing the
    URL another way)."""
    if not isinstance(cik10, str) or not _CIK_RE.match(cik10):
        raise ValueError(f"filing_document_url requires a 10-digit CIK string, got {cik10!r}")
    if not isinstance(accession, str) or not _ACCESSION_RE.match(accession):
        raise ValueError(f"filing_document_url requires a validated accession number, got {accession!r}")
    if not isinstance(filename, str) or not _FILENAME_RE.match(filename):
        raise ValueError(f"filing_document_url requires a validated filename, got {filename!r}")
    accession_nodash = accession.replace("-", "")
    return f"https://{_WWW_HOST}{_WWW_REQUIRED_PATH_PREFIX}{int(cik10)}/{accession_nodash}/{filename}"


class _IndexTableProbe(HTMLParser):
    """A minimal, standalone `Type`-header-cell detector for
    `_validate_index_html` — deliberately NOT `edgar_html.parse_index_table`
    (this module stays self-contained; `app.services.edgar_ingest` already
    depends on `sec_edgar`, and a reverse or sideways dependency here would
    only exist to serve a validity check this coarse). Tracks only "am I
    inside some `<table>`'s `<tr>`'s `<td>`/`<th>`", not table boundaries or
    row grouping — good enough to tell a real index page from an error
    page, which is all a `validate(body) -> bool` callback needs to do."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.found_type_header = False
        self._table_depth = 0
        self._in_cell = False
        self._cell_chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag == "table":
            self._table_depth += 1
        elif tag in ("td", "th") and self._table_depth > 0:
            self._in_cell = True
            self._cell_chunks = []

    def handle_endtag(self, tag: str) -> None:
        if tag in ("td", "th") and self._in_cell:
            if "".join(self._cell_chunks).strip() == "Type":
                self.found_type_header = True
            self._in_cell = False
            self._cell_chunks = []
        elif tag == "table" and self._table_depth > 0:
            self._table_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._in_cell:
            self._cell_chunks.append(data)


def _validate_index_html(body: bytes) -> bool:
    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        return False
    probe = _IndexTableProbe()
    try:
        probe.feed(text)
    except Exception:
        return False
    return probe.found_type_header


def _validate_filing_document(body: bytes) -> bool:
    """A non-empty body that, if under `_ERROR_MARKER_BODY_LIMIT` bytes,
    does not contain any of `_ERROR_PAGE_MARKERS`. The size gate matters: a
    multi-megabyte 10-K legitimately containing the substring "503" (a rule
    number, a dollar figure) must never be treated as an error page — only
    a SHORT body plausibly IS one (the research note's own documented
    shape)."""
    if not body:
        return False
    if len(body) < _ERROR_MARKER_BODY_LIMIT:
        for marker in _ERROR_PAGE_MARKERS:
            if marker in body:
                return False
    return True


def fetch_filing_index(cik10: str, accession: str) -> tuple[bytes, str, datetime, str]:
    """Fetch a filing's `-index.htm` documents-table page. Validates that
    the parsed body contains a table with a `Type` header cell — a real
    index page's own documents table always has one; an error page never
    does."""
    url = filing_index_url(cik10, accession)
    return _fetch(url, validate=_validate_index_html)


def fetch_filing_document(cik10: str, accession: str, filename: str) -> tuple[bytes, str, datetime, str]:
    """Fetch one document listed in a filing's index (an EX-21 exhibit, or
    the primary 10-K body). `filename` must already have come from a
    validated `Document`/`primaryDocument` value — see `filing_document_
    url`'s docstring."""
    url = filing_document_url(cik10, accession, filename)
    return _fetch(url, validate=_validate_filing_document)
