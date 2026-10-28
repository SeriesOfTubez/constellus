"""Wayback Machine CDX index lookup (planning#280 S5c-b2a).

Used by archive-first page capture: what is the newest non-error capture of a
domain since a given time? One query to the CDX index answers exactly that.
Decided 2026-10-28 after a security review: the availability API sometimes
answers "no snapshot" falsely and reports only the single latest capture
(which may be an error page); under a restricting posture a "no" permits a
live visit, so the "no" must be authoritative.

The only endpoint called is the fixed CDX URL; never a `/save/` endpoint and
never anything the response or a user supplies. The response is untrusted: it
is size-capped and strictly validated, only its timestamp and status columns
are read, and any `original` URL is never requested or used (the job URL is
built by `snapshot_url` from the validated timestamp and our own validated
domain). Redirects are not followed.

`latest_snapshot` returns a Snapshot, None (an explicit "no capture in the
window"), or raises WaybackUnavailable (the lookup could not give an answer,
or the answer was not exactly the expected shape: the caller must not treat
that as "no snapshot").
"""

import json
import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import httpx

from app.core import ssrf

log = logging.getLogger(__name__)

CDX_URL = "https://web.archive.org/cdx/search/cdx"
ARCHIVE_HOST = "web.archive.org"
LOOKUP_TIMEOUT_S = 10.0
LOOKUP_DEADLINE_S = 20.0  # wall clock for the whole body read
RESPONSE_MAX_BYTES = 64 * 1024
_TS_RE = re.compile(r"[0-9]{14}")
_STATUS_RE = re.compile(r"[23][0-9]{2}")
_HEADER = ["timestamp", "statuscode"]


class WaybackUnavailable(Exception):
    """The lookup could not give an answer."""


@dataclass(frozen=True)
class Snapshot:
    timestamp: str
    captured_at: datetime  # UTC, aware


def snapshot_url(snapshot: Snapshot, domain: str) -> str:
    return f"https://{ARCHIVE_HOST}/web/{snapshot.timestamp}/https://{domain}/"


def _unavailable(why: str) -> WaybackUnavailable:
    log.warning("wayback: lookup unavailable: %s", why)
    return WaybackUnavailable(why)


def latest_snapshot(domain: str, now: datetime, since: datetime) -> Snapshot | None:
    params = {
        "url": f"{domain}/",
        "output": "json",
        "fl": "timestamp,statuscode",
        "from": since.strftime("%Y%m%d%H%M%S"),
        "filter": "statuscode:[23]..",
        "limit": "-1",
    }
    deadline = time.monotonic() + LOOKUP_DEADLINE_S
    try:
        with ssrf.ssrf_safe_client(timeout=LOOKUP_TIMEOUT_S) as client:
            with client.stream("GET", CDX_URL, params=params) as resp:
                if resp.status_code != 200:
                    raise _unavailable(f"status {resp.status_code}")
                body = bytearray()
                for chunk in resp.iter_bytes():
                    body.extend(chunk)
                    if len(body) > RESPONSE_MAX_BYTES:
                        raise _unavailable("response too large")
                    # httpx's timeout is per operation: a slow drip under the
                    # byte cap would otherwise hold the request open for days.
                    if time.monotonic() > deadline:
                        raise _unavailable("lookup deadline exceeded")
    except httpx.HTTPError as e:
        raise _unavailable(f"transport error {type(e).__name__}") from e

    try:
        data = json.loads(bytes(body))
    except (ValueError, RecursionError):
        raise _unavailable("invalid JSON")
    if not isinstance(data, list):
        raise _unavailable("unexpected top-level value")
    if not data:
        return None  # explicit: no capture in the window
    if data[0] != _HEADER:
        raise _unavailable("unexpected header row")
    if len(data) == 1:
        return None  # header only: no capture in the window
    if len(data) > 2:
        raise _unavailable("more rows than limit=-1 allows")
    row = data[1]
    if not isinstance(row, list) or len(row) != 2 or not all(isinstance(v, str) for v in row):
        raise _unavailable("malformed row")
    ts, status = row
    if _TS_RE.fullmatch(ts) is None:
        raise _unavailable("bad timestamp")
    if _STATUS_RE.fullmatch(status) is None:
        raise _unavailable("bad status")
    try:
        captured_at = datetime.strptime(ts, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError:
        raise _unavailable("unparseable timestamp")
    if captured_at < since:
        raise _unavailable("capture older than the requested window")
    if captured_at - now > timedelta(days=1):
        raise _unavailable("timestamp in the future")
    return Snapshot(timestamp=ts, captured_at=captured_at)
