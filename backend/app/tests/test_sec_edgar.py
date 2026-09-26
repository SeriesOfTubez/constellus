"""Coverage for app.services.sec_edgar (planning#213, L4 slice 1) — the
`data.sec.gov` client's retry shapes, host allowlist, rate limiting and
headers.

Every test spies on the TRANSPORT (`httpx.MockTransport`, via
`_ScriptedTransport` below — copied from `test_llm_connector.py`'s own
helper, per the spec's "copy that pattern, do not invent another") and
asserts on the actual REQUESTS it received, never on a wrapper.

No live SEC call: every response is scripted. No real CIK: every CIK here
is a synthetic 10-digit string starting with "99" — real SEC CIKs are
sequential from a much lower range (Apple's is 0000320193; the CIK
counter is still well under 2,000,000 as of this writing), so a
"99########" value can never collide with a real filer.

Run with:  backend/scripts/test.ps1 app/tests/test_sec_edgar.py
       or: pytest app/tests/test_sec_edgar.py
"""

import itertools
import json

import httpx
import pytest

from app.core.config import settings
from app.services import sec_edgar

_CIK = "9900000001"
_UA = "planning213-tests contact@example.invalid"


def _submissions_body(*, cik: str = _CIK, name: str = "Example Holdings A", former_names=None, recent=None, files=None) -> bytes:
    payload = {
        "cik": cik,
        "name": name,
        "formerNames": former_names if former_names is not None else [],
        "filings": {
            "recent": recent if recent is not None else {"form": [], "accessionNumber": [], "filingDate": [], "items": []},
            "files": files if files is not None else [],
        },
    }
    return json.dumps(payload).encode()


def _page_body(*, recent=None) -> bytes:
    data = recent if recent is not None else {"form": [], "accessionNumber": [], "filingDate": [], "items": []}
    return json.dumps(data).encode()


class _ScriptedTransport:
    """Serves a scripted sequence of `httpx.Response`s in order and records
    every `httpx.Request` it received (copied from `test_llm_connector.py`'s
    `_ScriptedTransport` — the spec asks not to invent a second pattern)."""

    def __init__(self, responses: list[httpx.Response]):
        self._responses = list(responses)
        self.requests: list[httpx.Request] = []

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if not self._responses:
            raise AssertionError(
                f"_ScriptedTransport ran out of scripted responses after {len(self.requests)} request(s)"
            )
        return self._responses.pop(0)

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)


@pytest.fixture(autouse=True)
def _set_user_agent(monkeypatch):
    monkeypatch.setattr(settings, "sec_user_agent", _UA)


def _fast_clock():
    """A fake `_monotonic` that advances 1s per call — far more than
    `_MIN_REQUEST_INTERVAL_S` (0.125s), so `_rate_limit()` never sleeps
    between the scripted attempts within one test. Used by every
    RETRY-shape test below so the ONE sleep it asserts on is unambiguously
    the retry backoff, not an incidental rate-limit wait between two real
    attempts a few microseconds apart (rate limiting itself is covered
    separately, below)."""
    return itertools.count(0, 1.0).__next__


# ── retry shapes ─────────────────────────────────────────────────────────────

def test_200_with_short_error_body_is_retried_then_succeeds():
    """The research note's own documented shape: an HTTP 200 whose body is a
    short non-JSON string reading "503 Service Unavailable" — a status-code
    check alone would treat this as success."""
    good = _submissions_body()
    scripted = _ScriptedTransport([
        httpx.Response(200, content=b"503 Service Unavailable"),
        httpx.Response(200, content=good, headers={"content-type": "application/json"}),
    ])
    sleeps: list[float] = []
    sec_edgar._transport = scripted.transport
    sec_edgar._sleep = sleeps.append
    sec_edgar._monotonic = _fast_clock()
    try:
        content, content_type, fetched_at, url = sec_edgar.fetch_submissions(_CIK)
    finally:
        sec_edgar._transport = None
        sec_edgar._sleep = __import__("time").sleep
        sec_edgar._monotonic = __import__("time").monotonic

    assert content == good
    assert len(scripted.requests) == 2
    assert len(sleeps) == 1


def test_real_503_status_is_retried_then_succeeds():
    """2026-09-24 decisions comment: a REAL HTTP 503 status was also
    observed against SEC, distinct from the 200-with-short-body shape."""
    good = _submissions_body()
    scripted = _ScriptedTransport([
        httpx.Response(503, content=b"Service Unavailable"),
        httpx.Response(200, content=good),
    ])
    sleeps: list[float] = []
    sec_edgar._transport = scripted.transport
    sec_edgar._sleep = sleeps.append
    sec_edgar._monotonic = _fast_clock()
    try:
        content, _, _, _ = sec_edgar.fetch_submissions(_CIK)
    finally:
        sec_edgar._transport = None
        sec_edgar._sleep = __import__("time").sleep
        sec_edgar._monotonic = __import__("time").monotonic

    assert content == good
    assert len(scripted.requests) == 2
    assert len(sleeps) == 1


def test_429_with_retry_after_honours_the_header():
    good = _submissions_body()
    scripted = _ScriptedTransport([
        httpx.Response(429, content=b"slow down", headers={"Retry-After": "7"}),
        httpx.Response(200, content=good),
    ])
    sleeps: list[float] = []
    sec_edgar._transport = scripted.transport
    sec_edgar._sleep = sleeps.append
    sec_edgar._monotonic = _fast_clock()
    try:
        sec_edgar.fetch_submissions(_CIK)
    finally:
        sec_edgar._transport = None
        sec_edgar._sleep = __import__("time").sleep
        sec_edgar._monotonic = __import__("time").monotonic

    assert sleeps == [7.0]


def test_all_attempts_fail_raises_sec_fetch_error():
    scripted = _ScriptedTransport([httpx.Response(503, content=b"nope") for _ in range(5)])
    sec_edgar._transport = scripted.transport
    sec_edgar._sleep = lambda _s: None
    try:
        with pytest.raises(sec_edgar.SecFetchError):
            sec_edgar.fetch_submissions(_CIK)
    finally:
        sec_edgar._transport = None
        sec_edgar._sleep = __import__("time").sleep

    assert len(scripted.requests) == 5


def test_403_is_never_retried():
    scripted = _ScriptedTransport([httpx.Response(403, content=b"forbidden")])
    sec_edgar._transport = scripted.transport
    sec_edgar._sleep = lambda _s: (_ for _ in ()).throw(AssertionError("403 must not sleep/retry"))
    try:
        with pytest.raises(sec_edgar.SecFetchError, match="SEC_USER_AGENT"):
            sec_edgar.fetch_submissions(_CIK)
    finally:
        sec_edgar._transport = None
        sec_edgar._sleep = __import__("time").sleep

    assert len(scripted.requests) == 1


def test_404_raises_sec_not_found_without_retry():
    scripted = _ScriptedTransport([httpx.Response(404, content=b"not found")])
    sec_edgar._transport = scripted.transport
    try:
        with pytest.raises(sec_edgar.SecNotFound):
            sec_edgar.fetch_submissions(_CIK)
    finally:
        sec_edgar._transport = None

    assert len(scripted.requests) == 1


# ── host allowlist ───────────────────────────────────────────────────────────

def test_non_allowlisted_host_raises_value_error_with_zero_requests():
    scripted = _ScriptedTransport([httpx.Response(200, content=b"{}")])
    sec_edgar._transport = scripted.transport
    try:
        with pytest.raises(ValueError):
            sec_edgar._fetch("https://evil.example.invalid/x", validate=lambda _b: True)
    finally:
        sec_edgar._transport = None

    assert scripted.requests == []


def test_http_scheme_on_the_allowlisted_host_raises_value_error_with_zero_requests():
    scripted = _ScriptedTransport([httpx.Response(200, content=b"{}")])
    sec_edgar._transport = scripted.transport
    try:
        with pytest.raises(ValueError):
            sec_edgar._fetch("http://data.sec.gov/submissions/x.json", validate=lambda _b: True)
    finally:
        sec_edgar._transport = None

    assert scripted.requests == []


def test_invalid_page_name_raises_value_error_and_is_never_requested():
    scripted = _ScriptedTransport([httpx.Response(200, content=_page_body())])
    sec_edgar._transport = scripted.transport
    try:
        with pytest.raises(ValueError):
            sec_edgar.fetch_submissions_page("not-a-real-page-name.json")
    finally:
        sec_edgar._transport = None

    assert scripted.requests == []


def test_invalid_cik_raises_value_error_and_is_never_requested():
    scripted = _ScriptedTransport([httpx.Response(200, content=_submissions_body())])
    sec_edgar._transport = scripted.transport
    try:
        with pytest.raises(ValueError):
            sec_edgar.fetch_submissions("not-ten-digits")
    finally:
        sec_edgar._transport = None

    assert scripted.requests == []


# ── rate limit ───────────────────────────────────────────────────────────────

def test_rate_limit_sleeps_at_least_the_remaining_interval():
    """Drives `_monotonic` directly rather than the real clock: two
    back-to-back requests 0.01s apart (by the fake clock) must sleep at
    least `_MIN_REQUEST_INTERVAL_S - 0.01`."""
    good = _submissions_body()
    scripted = _ScriptedTransport([httpx.Response(200, content=good), httpx.Response(200, content=good)])

    clock = iter([100.0, 100.01])
    sleeps: list[float] = []
    sec_edgar._transport = scripted.transport
    sec_edgar._sleep = sleeps.append
    sec_edgar._monotonic = lambda: next(clock)
    sec_edgar._last_request_at = None
    try:
        sec_edgar.fetch_submissions(_CIK)
        sec_edgar.fetch_submissions(_CIK)
    finally:
        sec_edgar._transport = None
        sec_edgar._sleep = __import__("time").sleep
        sec_edgar._monotonic = __import__("time").monotonic
        sec_edgar._last_request_at = None

    expected_remaining = sec_edgar._MIN_REQUEST_INTERVAL_S - 0.01
    assert len(sleeps) == 1
    assert sleeps[0] >= expected_remaining - 1e-9


# ── headers ──────────────────────────────────────────────────────────────────

def test_user_agent_header_on_the_wire_equals_the_setting():
    """Asserted INSIDE the transport handler, on the actual outgoing
    request — never on a wrapper (R7 in `test_llm_connector.py`'s own
    naming for this discipline)."""
    seen_headers: list[httpx.Headers] = []

    def _handle(request: httpx.Request) -> httpx.Response:
        seen_headers.append(request.headers)
        return httpx.Response(200, content=_submissions_body())

    sec_edgar._transport = httpx.MockTransport(_handle)
    try:
        sec_edgar.fetch_submissions(_CIK)
    finally:
        sec_edgar._transport = None

    assert len(seen_headers) == 1
    assert seen_headers[0]["user-agent"] == _UA


def test_fetch_submissions_page_builds_the_allowlisted_url_and_validates_shape():
    good_recent = {
        "form": ["8-K"], "accessionNumber": ["0000099999-24-000001"],
        "filingDate": ["2024-01-02"], "items": ["2.01"],
    }
    scripted = _ScriptedTransport([httpx.Response(200, content=_page_body(recent=good_recent))])
    sec_edgar._transport = scripted.transport
    try:
        content, _, _, url = sec_edgar.fetch_submissions_page("CIK9900000001-submissions-001.json")
    finally:
        sec_edgar._transport = None

    assert url == "https://data.sec.gov/submissions/CIK9900000001-submissions-001.json"
    assert json.loads(content) == good_recent
