"""Archive-first page capture (planning#280 S5c-b2a): the Wayback lookup and the
producer branch. The TRANSPORT is mocked (httpx.MockTransport behind the client
factory wayback.py uses), never the `latest_snapshot` wrapper. Synthetic names
(fabrikam.com) only.

Run with:  backend/scripts/test.sh app/tests/test_page_capture_archive.py
"""

import json
import types
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from sqlalchemy.exc import IntegrityError

from app.core import ssrf
from app.core.database import SessionLocal
from app.models.app_settings import AppSetting
from app.models.observer import Observer
from app.models.page_capture import PageCapture
from app.services import app_settings, wayback
from app.services import page_capture as pc
from app.tests._engagement import make_engagement
from app.tests.test_page_capture_service import (  # noqa: F401 (fixtures + helpers)
    _auto, _candidate, _dom, _fresh, _no_job_files, _row_for, _rows_for, env, w,
)

TS = "20261020123456"
SNAP_AT = datetime(2026, 10, 20, 12, 34, 56, tzinfo=timezone.utc)
NOW = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)


def _ts(dt: datetime) -> str:
    return dt.strftime("%Y%m%d%H%M%S")


HEADER = ["timestamp", "statuscode"]
SINCE = NOW - timedelta(days=7)
NONE: list = []  # the real "no capture in the window" answer


def wire(ts: str = TS, status="200") -> list:
    """The real CDX wire shape: a header row, then the one newest matching row."""
    return [HEADER, [ts, status]]


def mock_wayback(monkeypatch, *, body=None, status=200, raw=None, headers=None, exc=None, chunks=None) -> list:
    """Route wayback.py's client factory onto a MockTransport; returns the list
    of every request the handler saw."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if exc is not None:
            raise exc
        if chunks is not None:
            return httpx.Response(status, content=iter(chunks), headers=headers)
        content = raw if raw is not None else json.dumps(body if body is not None else NONE).encode()
        return httpx.Response(status, content=content, headers=headers)

    def factory(timeout=15.0, follow_redirects=False, **kw):
        return httpx.Client(transport=httpx.MockTransport(handler), timeout=timeout, follow_redirects=follow_redirects)

    monkeypatch.setattr(wayback.ssrf, "ssrf_safe_client", factory)
    return seen


def _lookup():
    return wayback.latest_snapshot("fabrikam.com", NOW, SINCE)


def _unavailable(monkeypatch, **kw):
    seen = mock_wayback(monkeypatch, **kw)
    with pytest.raises(wayback.WaybackUnavailable):
        _lookup()
    assert len(seen) == 1
    return seen


# ── wayback unit ─────────────────────────────────────────────────────────────


def test_request_shape_and_fresh_snapshot(monkeypatch):
    seen = mock_wayback(monkeypatch, body=wire())
    snap = _lookup()
    assert len(seen) == 1
    req = seen[0]
    assert req.method == "GET" and req.url.host == "web.archive.org" and req.url.path == "/cdx/search/cdx"
    assert dict(req.url.params) == {
        "url": "fabrikam.com/", "output": "json", "fl": "timestamp,statuscode",
        "from": SINCE.strftime("%Y%m%d%H%M%S"), "filter": "statuscode:[23]..", "limit": "-1",
    }
    assert snap == wayback.Snapshot(TS, SNAP_AT)


@pytest.mark.parametrize("body", [[], [HEADER]])
def test_explicit_no_capture_is_none(monkeypatch, body):
    seen = mock_wayback(monkeypatch, body=body)
    assert _lookup() is None
    assert len(seen) == 1


def test_two_rows_is_unavailable(monkeypatch):
    _unavailable(monkeypatch, body=[HEADER, [TS, "200"], ["20261021123456", "200"]])


@pytest.mark.parametrize("body", [
    [["timestamp", "statuscode", "original"], [TS, "200", "http://fabrikam.com/"]],
    [["statuscode", "timestamp"], ["200", TS]],
    [[TS, "200"]],
    [HEADER, [TS, "200", "http://fabrikam.com/"]],
    [HEADER, [TS]],
    [HEADER, [TS, 200]],
    [HEADER, [20261020123456, "200"]],
    [HEADER, "x"],
    [HEADER, {"timestamp": TS}],
])
def test_wrong_shape_is_unavailable(monkeypatch, body):
    _unavailable(monkeypatch, body=body)


def test_extra_column_is_unavailable_so_no_response_url_is_ever_used(monkeypatch):
    hostile = "https://web.archive.org/save/https://evil.example/"
    _unavailable(monkeypatch, body=[["timestamp", "statuscode", "original"], [TS, "200", hostile]])


def test_job_url_is_built_from_the_validated_timestamp_and_our_domain(monkeypatch):
    mock_wayback(monkeypatch, body=wire())
    url = wayback.snapshot_url(_lookup(), "fabrikam.com")
    assert url == f"https://web.archive.org/web/{TS}/https://fabrikam.com/"


@pytest.mark.parametrize("status", ["-", "404", "", "2000", "500", "20", "abc"])
def test_bad_status_is_unavailable(monkeypatch, status):
    _unavailable(monkeypatch, body=wire(status=status))


# "2026102012345" (13 digits) parses under strptime (a one-digit %S): only the regex refuses it.
@pytest.mark.parametrize("ts", ["2026", "abcdefghijklmn", "20261340000000", "202610201234567", "2026102012345", ""])
def test_bad_timestamp_is_unavailable(monkeypatch, ts):
    _unavailable(monkeypatch, body=wire(ts))


def test_capture_one_second_before_since_is_unavailable(monkeypatch):
    _unavailable(monkeypatch, body=wire(_ts(SINCE - timedelta(seconds=1))))


def test_capture_exactly_at_since_is_a_snapshot(monkeypatch):
    mock_wayback(monkeypatch, body=wire(_ts(SINCE)))
    assert _lookup() is not None


def test_future_timestamp_is_unavailable(monkeypatch):
    _unavailable(monkeypatch, body=wire(_ts(NOW + timedelta(days=2))))


@pytest.mark.parametrize("status", [429, 500, 404])
def test_non_200_is_unavailable(monkeypatch, status):
    _unavailable(monkeypatch, body=wire(), status=status)


def test_redirect_is_unavailable_and_not_followed(monkeypatch):
    _unavailable(monkeypatch, body=wire(), status=302, headers={"Location": "https://evil.example/x"})


@pytest.mark.parametrize("raw", [b"not json", b"{}", b'{"timestamp": "x"}', b'"x"', b"5", b"null"])
def test_malformed_bodies_are_unavailable(monkeypatch, raw):
    _unavailable(monkeypatch, raw=raw)


def test_deeply_nested_json_is_unavailable_not_recursion_error(monkeypatch):
    raw = b"[" * 60000
    assert len(raw) < wayback.RESPONSE_MAX_BYTES
    _unavailable(monkeypatch, raw=raw)


def test_oversize_body_is_unavailable(monkeypatch):
    pad = " " * (wayback.RESPONSE_MAX_BYTES + 1)
    _unavailable(monkeypatch, raw=(json.dumps(NONE) + pad).encode())


def test_body_at_the_cap_is_still_read(monkeypatch):
    raw = json.dumps(NONE).encode()
    raw += b" " * (wayback.RESPONSE_MAX_BYTES - len(raw))
    assert len(raw) == wayback.RESPONSE_MAX_BYTES
    seen = mock_wayback(monkeypatch, raw=raw)
    assert _lookup() is None
    assert len(seen) == 1


def test_transport_error_is_unavailable(monkeypatch):
    _unavailable(monkeypatch, exc=httpx.ConnectError("boom"))


def test_ssrf_block_is_unavailable(monkeypatch):
    _unavailable(monkeypatch, exc=ssrf.SSRFBlockedError("blocked"))


def test_slow_drip_past_the_deadline_is_unavailable(monkeypatch):
    raw = json.dumps(wire()).encode()
    half = len(raw) // 2
    seen = mock_wayback(monkeypatch, chunks=[raw[:half], raw[half:]])
    ticks = iter([0.0] + [wayback.LOOKUP_DEADLINE_S + 1] * 10)
    monkeypatch.setattr(wayback, "time", types.SimpleNamespace(monotonic=lambda: next(ticks)))
    with pytest.raises(wayback.WaybackUnavailable, match="deadline"):
        _lookup()
    assert len(seen) == 1


def test_chunked_body_within_the_deadline_is_read(monkeypatch):
    # Precondition for the deadline test: the same two-chunk delivery succeeds when time has not run out.
    raw = json.dumps(wire()).encode()
    half = len(raw) // 2
    seen = mock_wayback(monkeypatch, chunks=[raw[:half], raw[half:]])
    assert _lookup() == wayback.Snapshot(TS, SNAP_AT)
    assert len(seen) == 1


def test_lookup_goes_through_ssrf_safe_client_without_following_redirects(monkeypatch):
    calls = []

    def recorder(*args, **kwargs):
        calls.append((args, kwargs))
        return httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=NONE)))

    monkeypatch.setattr(ssrf, "ssrf_safe_client", recorder)
    assert _lookup() is None
    assert len(calls) == 1
    kwargs = calls[0][1]
    assert kwargs.get("timeout") == wayback.LOOKUP_TIMEOUT_S
    assert kwargs.get("follow_redirects", False) is not True


# ── producer ─────────────────────────────────────────────────────────────────


def _restricted(w):
    root = w.entity()
    eng = make_engagement(w.db, "pre_close", subject_entity_id=root.id)
    w.engagements.append(eng.id)
    w.db.refresh(root)
    return root


def _job(env, row) -> dict:
    return json.loads((env["spool"] / "jobs" / f"{row.id}.json").read_text())


def _assert_live(env, row, c):
    assert (row.source, row.archive_snapshot_at, row.archive_host) == ("live", None, None)
    assert row.requested_url == f"https://{c.value}/"
    job = _job(env, row)
    assert job["mode"] == "live" and job["url"] == f"https://{c.value}/"
    assert job["proxy_token"] == pc.proxy_token(str(row.id), "live", job["proxy_expires"])


def test_passive_only_fresh_snapshot_queues_an_archive_job(w, env, monkeypatch):
    c = _candidate(w, _restricted(w))
    ts = _ts(datetime.now(timezone.utc) - timedelta(days=2))
    seen = mock_wayback(monkeypatch, body=wire(ts))
    row = pc.request_capture(w.db, candidate_id=c.id, user=w.user(), manual=True)
    assert len(seen) == 1 and dict(seen[0].url.params)["url"] == f"{c.value}/"
    snap_url = f"https://web.archive.org/web/{ts}/https://{c.value}/"
    r = _fresh(row.id)
    assert r.source == "archive" and r.archive_host == "web.archive.org"
    assert r.archive_snapshot_at == datetime.strptime(ts, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    assert r.requested_url == snap_url
    job = _job(env, row)
    assert job["mode"] == "archive" and job["url"] == snap_url
    cid = str(row.id)
    assert job["proxy_token"] == pc.proxy_token(cid, "archive", job["proxy_expires"])
    assert job["proxy_token"] != pc.proxy_token(cid, "live", job["proxy_expires"])


def test_passive_only_no_capture_in_the_window_falls_back_to_a_live_job(w, env, monkeypatch):
    c = _candidate(w, _restricted(w))
    seen = mock_wayback(monkeypatch, body=[])
    row = pc.request_capture(w.db, candidate_id=c.id, user=w.user(), manual=True)
    assert len(seen) == 1
    _assert_live(env, _fresh(row.id), c)


class _FrozenDatetime(datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW if tz is None else NOW.astimezone(tz)


@pytest.mark.parametrize("stored,days", [(None, 7), ("30", 30), ("0", 7), ("91", 7)])
def test_from_param_is_now_minus_the_freshness_days(w, env, monkeypatch, cap_settings, stored, days):
    """`pc.datetime` is frozen at NOW so `from` is exact; a stored out-of-bounds value clamps to 7."""
    if stored is not None:
        cap_settings(ARCHIVE_FRESHNESS_DAYS_KEY=stored)
    monkeypatch.setattr(pc, "datetime", _FrozenDatetime)
    c = _candidate(w, _restricted(w))
    seen = mock_wayback(monkeypatch, body=[])
    pc.request_capture(w.db, candidate_id=c.id, user=w.user(), manual=True)
    assert len(seen) == 1
    assert dict(seen[0].url.params)["from"] == _ts(NOW - timedelta(days=days))


@pytest.mark.parametrize("stored", ["0", "91", "-3", "abc"])
def test_out_of_bounds_freshness_clamps_to_default(stored, cap_settings):
    cap_settings(ARCHIVE_FRESHNESS_DAYS_KEY=stored)
    with SessionLocal() as s:
        assert pc.archive_freshness_days(s) == 7


def test_lookup_failure_refuses_with_no_row_and_no_job(w, env, monkeypatch):
    c = _candidate(w, _restricted(w))
    seen = mock_wayback(monkeypatch, body=wire(), status=429)
    with pytest.raises(pc.CaptureRefused) as e:
        pc.request_capture(w.db, candidate_id=c.id, user=w.user(), manual=True)
    assert e.value.rule == "archive:lookup_unavailable"
    assert len(seen) == 1
    assert _rows_for(c.id) == 0 and _no_job_files(env) == []


def test_manual_bypasses_the_budget_but_not_the_lookup(w, env, monkeypatch):
    shared = _dom()
    other = _candidate(w, value=shared)
    _row_for(w, other, "done", finished_ago_days=1)
    c = _candidate(w, _restricted(w), value=shared)  # restricted posture, same domain, recent done capture
    seen = mock_wayback(monkeypatch, body=NONE)
    row = pc.request_capture(w.db, candidate_id=c.id, user=w.user(), manual=True)
    assert len(seen) == 1  # the budget was bypassed, the lookup still ran
    assert _fresh(row.id).status == "queued"


def test_budget_counts_an_archive_capture_and_refuses_before_the_lookup(w, env, monkeypatch):
    shared = _dom()
    other = _candidate(w, _restricted(w), value=shared)
    prior = _row_for(w, other, "done", finished_ago_days=1)
    prior.source, prior.archive_snapshot_at = "archive", SNAP_AT
    prior.archive_host = "web.archive.org"
    w.db.commit()
    c = _candidate(w, _restricted(w), value=shared)
    seen = mock_wayback(monkeypatch, body=wire())
    with pytest.raises(pc.CaptureRefused) as e:
        _auto(w, c)
    assert e.value.rule == "capture:revisit_budget"
    assert seen == [] and _rows_for(c.id) == 0 and _no_job_files(env) == []


def test_missing_proxy_key_refuses_before_the_lookup(w, env, monkeypatch):
    monkeypatch.delenv("CAPTURE_PROXY_KEY")
    c = _candidate(w, _restricted(w))
    seen = mock_wayback(monkeypatch, body=wire())
    with pytest.raises(pc.CaptureRefused) as e:
        pc.request_capture(w.db, candidate_id=c.id, user=w.user(), manual=True)
    assert e.value.rule == "capture:not_configured"
    assert seen == [] and _rows_for(c.id) == 0


def test_without_a_restricting_posture_there_is_no_lookup(w, env, monkeypatch):
    c = _candidate(w)
    seen = mock_wayback(monkeypatch, body=wire(), status=429)  # would refuse if it were consulted
    row = pc.request_capture(w.db, candidate_id=c.id, user=w.user(), manual=True)
    assert seen == []
    _assert_live(env, _fresh(row.id), c)


# ── migration / model ────────────────────────────────────────────────────────


def _insert(w, **over):
    c = _candidate(w)
    obs = w.db.query(Observer).filter(Observer.name == "page_capture").one()
    row = PageCapture(
        candidate_id=c.id, domain=c.value, observer_id=obs.id, requested_url=f"https://{c.value}/",
        user_agent_mode="stock", image_max_bytes=pc.DEFAULT_MAX_IMAGE_BYTES, **over,
    )
    w.db.add(row)
    return row


def test_default_insert_is_live(w):
    row = _insert(w)
    w.db.commit()
    assert _fresh(row.id).source == "live"


def test_archive_row_needs_its_fields(w):
    _insert(w, source="archive")
    with pytest.raises(IntegrityError):
        w.db.commit()
    w.db.rollback()
    ok = _insert(w, source="archive", archive_snapshot_at=SNAP_AT, archive_host="web.archive.org")
    w.db.commit()
    assert _fresh(ok.id).source == "archive"


def test_live_row_must_not_carry_archive_fields(w):
    _insert(w, archive_host="web.archive.org")
    with pytest.raises(IntegrityError):
        w.db.commit()
    w.db.rollback()


def test_bogus_source_violates_the_check(w):
    _insert(w, source="bogus", archive_snapshot_at=SNAP_AT, archive_host="web.archive.org")
    with pytest.raises(IntegrityError):
        w.db.commit()
    w.db.rollback()


# ── settings fixture (local, like the service tests') ────────────────────────


@pytest.fixture
def cap_settings():
    with SessionLocal() as s:
        row = s.get(AppSetting, pc.ARCHIVE_FRESHNESS_DAYS_KEY)
        before = row.value if row else None

    def set_(**kv):
        with SessionLocal() as s:
            for k, v in kv.items():
                app_settings.set_value(s, getattr(pc, k), str(v))

    yield set_
    with SessionLocal() as s:
        row = s.get(AppSetting, pc.ARCHIVE_FRESHNESS_DAYS_KEY)
        if before is None and row is not None:
            s.delete(row)
        elif row is not None:
            row.value = before
        s.commit()


# ── ingest: the rendered snapshot time is the evidence ───────────────────────

from app.tests.test_page_capture_service import _drop_result, _ingest, _result  # noqa: E402

REQ_AT = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)


def _arch(w, req_ts=TS, requested_at=REQ_AT, source="archive"):
    """A queued row; an archive one carries the provisional snapshot time."""
    over = {}
    if source == "archive":
        snap = datetime.strptime(req_ts, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        over = dict(archive_snapshot_at=snap, archive_host="web.archive.org")
    row = _insert(w, source=source, requested_at=requested_at, **over)
    c_value = row.domain
    row.requested_url = f"https://web.archive.org/web/{req_ts}/https://{c_value}/"
    w.db.commit()
    return row


def _run(w, env, row, final_url, **over):
    _drop_result(env, row, result=_result(row, final_url=final_url, **over))
    assert _ingest(w) == 1
    return _fresh(row.id)


def _wb(row, ts, flag=""):
    return f"https://web.archive.org/web/{ts}{flag}/https://{row.domain}/"


def test_rendered_equals_requested_is_done(w, env):
    row = _arch(w)
    r = _run(w, env, row, _wb(row, TS))
    assert (r.status, r.failure_reason, r.archive_snapshot_at) == ("done", None, SNAP_AT)


def test_rendered_differs_inside_window_records_the_rendered_time(w, env):
    row = _arch(w)
    rendered = SNAP_AT - timedelta(hours=5)
    r = _run(w, env, row, _wb(row, _ts(rendered)))
    assert r.status == "done" and r.archive_snapshot_at == rendered != SNAP_AT


def test_replay_flag_is_parsed(w, env):
    row = _arch(w)
    r = _run(w, env, row, _wb(row, "20261020123456", "id_"))
    assert r.status == "done" and r.archive_snapshot_at == SNAP_AT


def test_rendered_older_than_window_is_stale_and_still_recorded(w, env):
    row = _arch(w)
    rendered = REQ_AT - timedelta(days=30)
    r = _run(w, env, row, _wb(row, _ts(rendered)))
    assert (r.status, r.failure_reason) == ("failed", "archive_snapshot_stale")
    assert r.archive_snapshot_at == rendered  # CHECK safety: not nulled


def test_window_boundary_exact_done_one_second_older_stale(w, env):
    edge = REQ_AT - timedelta(days=7)
    a = _arch(w)
    ra = _run(w, env, a, _wb(a, _ts(edge)))
    assert (ra.status, ra.archive_snapshot_at) == ("done", edge)
    b = _arch(w)
    rb = _run(w, env, b, _wb(b, _ts(edge - timedelta(seconds=1))))
    assert (rb.status, rb.failure_reason) == ("failed", "archive_snapshot_stale")


def test_freshness_setting_is_honoured_at_ingest(w, env, cap_settings):
    cap_settings(ARCHIVE_FRESHNESS_DAYS_KEY=30)
    row = _arch(w)
    rendered = REQ_AT - timedelta(days=20)
    r = _run(w, env, row, _wb(row, _ts(rendered)))
    assert r.status == "done" and r.archive_snapshot_at == rendered


def test_rendered_in_the_future_beyond_a_day_is_stale(w, env):
    row = _arch(w)
    rendered = REQ_AT + timedelta(days=1, seconds=1)
    r = _run(w, env, row, _wb(row, _ts(rendered)))
    assert (r.status, r.failure_reason) == ("failed", "archive_snapshot_stale")
    assert r.archive_snapshot_at == rendered


@pytest.mark.parametrize("final", [
    None,
    "http://web.archive.org/web/20261020123456/https://fabrikam.com/",
    "https://example.org/web/20261020123456/https://fabrikam.com/",
    "https://web.archive.org:8443/web/20261020123456/https://fabrikam.com/",
    "https://web.archive.org/save/https://fabrikam.com/",
    "https://web.archive.org/web/2026102012345/https://fabrikam.com/",
])
def test_unreadable_final_url_is_unverified(w, env, final):
    row = _arch(w)
    r = _run(w, env, row, final)
    assert (r.status, r.failure_reason) == ("failed", "archive_snapshot_unverified")
    assert r.archive_snapshot_at == SNAP_AT  # untouched, still satisfies the CHECK


def test_capture_error_keeps_precedence_on_an_archive_row(w, env):
    row = _arch(w)
    r = _run(w, env, row, _wb(row, TS), error="boom")
    assert (r.status, r.failure_reason) == ("failed", "capture_error")


def test_live_row_with_archive_final_url_is_untouched(w, env):
    row = _arch(w, source="live")
    r = _run(w, env, row, _wb(row, TS))
    assert (r.status, r.archive_snapshot_at, r.archive_host) == ("done", None, None)
