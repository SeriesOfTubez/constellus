"""CPE index delta sync (planning#369): day-by-day walk, cursor pagination, refusal and
time-limit handling, pacing. Real constellus_test DB; the transport is faked; synthetic data.

Run with:  backend/scripts/test.sh app/tests/test_cpe_cve_sync.py
"""
from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.core.database import SessionLocal
from app.models.app_settings import AppSetting
from app.models.cpe_cve_range import CpeCveRange
from app.services import cpe_cve_sync as cs
from app.services.cpe_cve_index import parse_configurations, replace_cve_ranges

KEYS = (cs._CURSOR_KEY, cs._LAST_REFRESH_KEY, cs._SEEDED_KEY, cs.PAGE_SIZE_KEY, cs.RUN_TIME_LIMIT_KEY)
IN_SCOPE = [{"nodes": [{"cpeMatch": [
    {"criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", "vulnerable": True},
]}]}]


def _wipe():
    with SessionLocal() as s:
        s.query(AppSetting).filter(AppSetting.key.in_(KEYS)).delete(synchronize_session=False)
        s.query(CpeCveRange).filter(CpeCveRange.cve_id.like("CVE-2099-%")).delete(synchronize_session=False)
        s.commit()


@pytest.fixture(autouse=True)
def clean():
    _wipe()
    yield
    _wipe()


@pytest.fixture
def db():
    with SessionLocal() as s:
        yield s


def _today() -> date:
    return datetime.now(timezone.utc).date()


def _rec(n: int, configs=None) -> dict:
    return {"id": f"CVE-2099-{n:04d}", "configurations": IN_SCOPE if configs is None else configs,
            "vcConfigurations": []}


def _store(key: str, value: str) -> None:
    with SessionLocal() as s:
        cs._set_setting(s, key, value)


def _stored(key: str) -> str | None:
    with SessionLocal() as s:
        row = s.get(AppSetting, key)
        return row.value if row else None


def _ranges(cve_id: str) -> int:
    with SessionLocal() as s:
        return s.query(CpeCveRange).filter(CpeCveRange.cve_id == cve_id).count()


class _Resp:
    def __init__(self, status: int, body: dict):
        self.status_code, self._body, self.text = status, body, "refused" if status != 200 else "ok"

    def json(self):
        return self._body


class Fake:
    """Answers by (day, page index). `days`: {iso day: [(records, next_cursor_or_None), ...]}.
    A day not listed has one empty page. `fail`: {(day, idx): status}; `boom`: {(day, idx): exc}."""

    def __init__(self, days=None, fail=None, boom=None, on_call=None):
        self.days, self.fail, self.boom, self.on_call = days or {}, fail or {}, boom or {}, on_call
        self.calls: list[dict] = []
        self._last: dict[str, tuple[int, str | None]] = {}

    def __call__(self, url, **kw):
        p = dict(kw["params"])
        self.calls.append(p)
        day = p["lastModStartDate"]
        assert p["lastModEndDate"] == day
        if self.on_call:
            self.on_call(self, p)
        if "start_cursor" in p:
            idx = 0
        else:
            last_idx, last_next = self._last[day]
            assert p["cursor"] == last_next, "cursor must be the previous page's next_cursor"
            idx = last_idx + 1
        pages = self.days.get(day) or [([], None)]
        records, nxt = pages[idx]
        self._last[day] = (idx, nxt)
        if (day, idx) in self.boom:
            raise self.boom[(day, idx)]
        if (day, idx) in self.fail:
            return _Resp(self.fail[(day, idx)], {})
        meta = {"total_documents": 1, "limit": p["limit"]}
        if nxt:
            meta["next_cursor"] = nxt
        return _Resp(200, {"_meta": meta, "data": records})

    @property
    def days_requested(self) -> list[str]:
        out: list[str] = []
        for c in self.calls:
            if not out or out[-1] != c["lastModStartDate"]:
                out.append(c["lastModStartDate"])
        return out


class Clock:
    def __init__(self, tick=0.0):
        self.t, self.tick = 0.0, tick

    def __call__(self):
        self.t += self.tick
        return self.t


@pytest.fixture
def wire(monkeypatch):
    def _wire(fake, clock=None, headers=True):
        monkeypatch.setattr(cs, "connector_get", fake)
        monkeypatch.setattr(cs, "_vc_headers", lambda db: {"Authorization": "Bearer test"} if headers else None)
        clk = clock or Clock()
        # Replace the module's `time` reference only; the real time.monotonic stays untouched.
        monkeypatch.setattr(cs, "time", SimpleNamespace(monotonic=clk))
        return fake
    return _wire


def _iso(d: date) -> str:
    return d.isoformat()


def _pages(*record_lists, prefix="c"):
    """Pages with unique cursors between them; the last page has no next_cursor."""
    n = len(record_lists)
    return [(recs, f"{prefix}{i}" if i + 1 < n else None) for i, recs in enumerate(record_lists)]


# a
def test_multi_day_window_oldest_first(db, wire):
    today = _today()
    start = today - timedelta(days=3)
    days = [start + timedelta(days=i) for i in range(4)]
    fake = wire(Fake(days={_iso(days[1]): _pages([_rec(1)])}))
    _store(cs._CURSOR_KEY, _iso(start))
    r = cs.delta_from_vulncheck(db)
    assert fake.days_requested == [_iso(d) for d in days]
    assert all(c["lastModStartDate"] == c["lastModEndDate"] and c["start_cursor"] == "true" for c in fake.calls)
    assert (r.stopped, r.days_done, r.days_left) == ("done", 4, 0)
    assert r.written == 1
    assert _stored(cs._CURSOR_KEY) == _iso(today)
    assert _ranges("CVE-2099-0001") == 1


# b
def test_cursor_pagination_inside_a_day(db, wire):
    today = _today()
    fake = wire(Fake(days={_iso(today): _pages([_rec(1)], [_rec(2)], [_rec(3)], prefix="tok")}))
    _store(cs._CURSOR_KEY, _iso(today))
    r = cs.delta_from_vulncheck(db)
    assert len(fake.calls) == 3
    assert fake.calls[0]["start_cursor"] == "true" and "cursor" not in fake.calls[0]
    assert fake.calls[1]["cursor"] == "tok0" and "start_cursor" not in fake.calls[1]
    assert fake.calls[2]["cursor"] == "tok1" and "start_cursor" not in fake.calls[2]
    assert not any("page" in c for c in fake.calls)
    assert r.written == 3
    for n in (1, 2, 3):
        assert _ranges(f"CVE-2099-{n:04d}") == 1


# c
def test_refusal_midway_keeps_progress(db, wire):
    today = _today()
    start = today - timedelta(days=3)
    d = [start + timedelta(days=i) for i in range(4)]
    fake = wire(Fake(
        days={_iso(d[0]): _pages([_rec(1)]), _iso(d[1]): _pages([_rec(2)]),
              _iso(d[2]): _pages([_rec(3)], [_rec(4)])},
        fail={(_iso(d[2]), 1): 400},
    ))
    _store(cs._CURSOR_KEY, _iso(start))
    r = cs.delta_from_vulncheck(db)
    assert (r.stopped, r.days_done) == ("source_refused", 2)
    assert r.days_left == (today - d[2]).days + 1 == 2
    assert _stored(cs._CURSOR_KEY) == _iso(d[2])
    assert fake.days_requested == [_iso(d[0]), _iso(d[1]), _iso(d[2])]
    assert len([c for c in fake.calls if c["lastModStartDate"] == _iso(d[2])]) == 2  # refusal was reached
    assert _iso(d[3]) not in fake.days_requested


# d
def test_refusal_on_the_first_request(db, wire):
    today = _today()
    start = today - timedelta(days=2)
    fake = wire(Fake(fail={(_iso(start), 0): 429}))
    _store(cs._CURSOR_KEY, _iso(start))
    r = cs.delta_from_vulncheck(db)
    assert len(fake.calls) == 1
    assert (r.stopped, r.days_done) == ("source_refused", 0)
    assert _stored(cs._CURSOR_KEY) == _iso(start)


# e
def test_time_limit_is_checked_between_days_only(db, wire):
    today = _today()
    start = today - timedelta(days=2)
    d1, d2 = _iso(start), _iso(start + timedelta(days=1))

    def jump(fake, p):  # the limit passes while day 1 is being fetched
        clock.t += 10_000

    clock = Clock()
    fake = wire(Fake(days={d1: _pages([_rec(1)], [_rec(2)], [_rec(3)])}, on_call=jump), clock=clock)
    _store(cs._CURSOR_KEY, d1)
    r = cs.delta_from_vulncheck(db)
    assert len([c for c in fake.calls if c["lastModStartDate"] == d1]) == 3  # day 1 finished all pages
    assert d2 not in fake.days_requested
    assert (r.stopped, r.days_done) == ("time_limit", 1)
    assert r.days_left == 2
    assert _stored(cs._CURSOR_KEY) == d2


# f
def test_time_limit_never_blocks_the_first_day(db, wire):
    today = _today()
    start = today - timedelta(days=3)
    fake = wire(Fake(), clock=Clock(tick=10_000))  # every clock read is far past the limit
    _store(cs._CURSOR_KEY, _iso(start))
    r = cs.delta_from_vulncheck(db)
    assert fake.days_requested == [_iso(start)]
    assert (r.stopped, r.days_done) == ("time_limit", 1)


# g
def test_caught_up_run_fetches_today_and_rests_there(db, wire):
    today = _today()
    fake = wire(Fake())
    _store(cs._CURSOR_KEY, _iso(today))
    r = cs.delta_from_vulncheck(db)
    assert fake.days_requested == [_iso(today)]
    assert (r.stopped, r.days_done, r.days_left) == ("done", 1, 0)
    assert _stored(cs._CURSOR_KEY) == _iso(today)


# h
def test_repeated_provider_cursor_raises_and_the_day_stays_due(db, wire):
    today = _today()
    start = today - timedelta(days=1)
    fake = wire(Fake(days={_iso(start): [([_rec(1)], "same"), ([_rec(2)], "same"), ([_rec(3)], None)]}))
    _store(cs._CURSOR_KEY, _iso(start))
    with pytest.raises(RuntimeError, match="cursor repeated"):
        cs.delta_from_vulncheck(db)
    assert len(fake.calls) == 2  # the guard was reached on the second page
    assert _stored(cs._CURSOR_KEY) == _iso(start)


# i
def test_transport_exception_propagates_and_keeps_finished_days(db, wire):
    today = _today()
    start = today - timedelta(days=3)
    d = [start + timedelta(days=i) for i in range(3)]
    fake = wire(Fake(boom={(_iso(d[2]), 0): ConnectionError("down")}))
    _store(cs._CURSOR_KEY, _iso(start))
    with pytest.raises(ConnectionError):
        cs.delta_from_vulncheck(db)
    assert fake.days_requested == [_iso(x) for x in d]
    assert _stored(cs._CURSOR_KEY) == _iso(d[2])


# j
def test_no_key_is_not_configured_and_makes_no_calls(db, wire):
    fake = wire(Fake(), headers=False)
    _store(cs._CURSOR_KEY, _iso(_today()))
    r = cs.delta_from_vulncheck(db)
    assert (r.stopped, r.written, r.days_done, r.days_left) == ("not_configured", 0, 0, 0)
    assert fake.calls == []


# k
def test_refresh_stamps_last_refresh_only_when_done(db, wire):
    today = _today()
    _store(cs._SEEDED_KEY, "1")

    fake = wire(Fake())
    _store(cs._CURSOR_KEY, _iso(today))
    out = cs.refresh(db)
    assert set(out) == {"seeded", "delta", "days_done", "days_left", "stopped"}
    assert out["stopped"] == "done" and fake.calls
    assert _stored(cs._LAST_REFRESH_KEY) is not None

    with SessionLocal() as s:
        s.query(AppSetting).filter(AppSetting.key == cs._LAST_REFRESH_KEY).delete()
        s.commit()

    start = today - timedelta(days=2)
    fake = wire(Fake(fail={(_iso(start), 0): 500}))
    _store(cs._CURSOR_KEY, _iso(start))
    out = cs.refresh(db)
    assert out["stopped"] == "source_refused" and len(fake.calls) == 1
    assert _stored(cs._LAST_REFRESH_KEY) is None

    fake = wire(Fake(), clock=Clock(tick=10_000))
    _store(cs._CURSOR_KEY, _iso(start))
    out = cs.refresh(db)
    assert out["stopped"] == "time_limit" and out["days_done"] == 1 and len(fake.calls) == 1
    assert _stored(cs._LAST_REFRESH_KEY) is None


# l
def test_pacing_defaults_and_bounds(db, wire):
    assert cs.pacing(db) == cs.DeltaPacing(500, 600)
    _store(cs.PAGE_SIZE_KEY, "1000")
    _store(cs.RUN_TIME_LIMIT_KEY, "1200")
    assert cs.pacing(db) == cs.DeltaPacing(1000, 1200)
    for page, limit in (("49", "59"), ("2001", "3601"), ("abc", "xyz"), ("", "")):
        _store(cs.PAGE_SIZE_KEY, page)
        _store(cs.RUN_TIME_LIMIT_KEY, limit)
        assert cs.pacing(db) == cs.DeltaPacing(500, 600), (page, limit)


def test_stored_page_size_reaches_the_wire(db, wire):
    _store(cs.PAGE_SIZE_KEY, "1000")
    fake = wire(Fake())
    _store(cs._CURSOR_KEY, _iso(_today()))
    cs.delta_from_vulncheck(db)
    assert [c["limit"] for c in fake.calls] == [1000]


# m
def test_an_old_cursor_is_not_skipped_forward(db, wire):
    stored = _today() - timedelta(days=112)
    fake = wire(Fake(), clock=Clock(tick=10_000))
    _store(cs._CURSOR_KEY, _iso(stored))
    r = cs.delta_from_vulncheck(db)
    assert fake.calls and fake.calls[0]["lastModStartDate"] == _iso(stored)
    assert fake.days_requested == [_iso(stored)]
    assert (r.stopped, r.days_done) == ("time_limit", 1)
    assert _stored(cs._CURSOR_KEY) == _iso(stored + timedelta(days=1))


# n
def test_a_cve_that_left_scope_loses_its_rows(db, wire):
    now = datetime.now(timezone.utc)
    rows = parse_configurations("CVE-2099-0007", IN_SCOPE, "vulncheck", now)
    assert rows
    replace_cve_ranges(db, "CVE-2099-0007", rows)
    db.commit()
    assert _ranges("CVE-2099-0007") == len(rows)
    today = _today()
    fake = wire(Fake(days={_iso(today): _pages([_rec(7, configs=[])])}))
    _store(cs._CURSOR_KEY, _iso(today))
    cs.delta_from_vulncheck(db)
    assert len(fake.calls) == 1
    assert _ranges("CVE-2099-0007") == 0
