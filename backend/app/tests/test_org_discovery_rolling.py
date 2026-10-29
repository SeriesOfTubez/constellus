"""The rolling re-discovery job (planning#277 S6b step b).

Ordering, due/eligibility selection, stop conditions and slot handling run the
REAL selection SQL over real rows, with the three runner units replaced by
recording stubs. One end-to-end test runs the real units with stubbed
transports. `_read_due` is wrapped only to scope the run to the rows THIS test
made. Synthetic names; RFC 3849 addresses from a counter.

Run with:  scripts/test.sh app/tests/test_org_discovery_rolling.py
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy import update

from app.core.database import SessionLocal
from app.models.org_entity import OrgEntity
from app.models.scope_candidate import ScopeCandidate
from app.services import hosting_classifier as hc
from app.services import scheduler
from app.services.org_discovery import rolling, runner
from app.services.org_discovery.domain_facts import DomainFacts
from app.tests._org_world import World, hexid  # noqa: F401
from app.tests.test_org_discovery_refresh_stamps import (  # noqa: F401  (w is a fixture)
    Transport, _claimed_domain, _dom, _limiter, _root_row, _row, _seed_ip, _ip, _stub_rir, w,
)
from app.tests.test_org_discovery_schema import _insert_candidate


@pytest.fixture(autouse=True)
def _clean_slots_and_clock(monkeypatch):
    runner._recheck_running.clear()
    monkeypatch.setattr(rolling, "_sleep", lambda s: None)
    yield
    runner._recheck_running.clear()


def _scope(monkeypatch, *roots):
    """Limit the run to these roots' units; the SQL itself is untouched."""
    ids = {r.id for r in roots}
    real = rolling._read_due
    monkeypatch.setattr(rolling, "_read_due", lambda now: [u for u in real(now) if u[2] in ids])


class Calls:
    """Recording stubs for the three runner units."""

    def __init__(self, monkeypatch, outcome=runner.UNIT_OK):
        self.log: list[tuple[str, uuid.UUID]] = []
        self.outcome = outcome
        self.hook = None
        monkeypatch.setattr(runner, "refresh_claimed_domain", lambda cid: self._do("claimed", cid))
        monkeypatch.setattr(runner, "refresh_root", lambda rid, *, fresh_since: (self._do("root", rid), None, None))
        monkeypatch.setattr(runner, "verify_new_candidates", self._verify)

    def _do(self, kind, uid):
        self.log.append((kind, uid))
        if self.hook:
            self.hook(kind, uid)
        return self.outcome

    def _verify(self, ids):
        self._do("open", ids[0])
        return runner.VerifyReport(pairs_checked=1)

    @property
    def ids(self):
        return [u for _, u in self.log]


def _set(model, row_id, at_attr, at, failed_attr, failed=False):
    db = SessionLocal()
    try:
        db.execute(update(model).where(model.id == row_id).values({at_attr: at, failed_attr: failed}))
        db.commit()
    finally:
        db.close()


def _claimed_at(w, root, at, failed=False, tag="c"):
    cid = _claimed_domain(w, root, _dom(tag))
    _set(ScopeCandidate, cid, "rediscovered_at", at, "rediscovery_failed", failed)
    return cid


def _open_at(w, root, at, failed=False, tag="o"):
    oid = _insert_candidate(w.db, root.id, value=_dom(tag), status="open")
    _set(ScopeCandidate, oid, "reverified_at", at, "reverify_failed", failed)
    return oid


def _root_at(root, at, failed=False):
    _set(OrgEntity, root.id, "rediscovered_at", at, "rediscovery_failed", failed)


def _ago(**kw):
    return datetime.now(timezone.utc) - timedelta(**kw)


# 1 ── order
def test_order_never_first_then_oldest_mixed_kinds(w, monkeypatch):
    root = w.ours()
    _root_at(root, _ago(days=8))
    c_never = _claimed_at(w, root, None)
    o_never = _open_at(w, root, None)
    c_12 = _claimed_at(w, root, _ago(days=12))
    o_10 = _open_at(w, root, _ago(days=10))
    _scope(monkeypatch, root)
    calls = Calls(monkeypatch)

    result = rolling.run_rediscovery_tick()

    assert calls.ids == [c_never, o_never, c_12, o_10, root.id]  # never (claimed before open), then oldest
    assert [k for k, _ in calls.log] == ["claimed", "open", "claimed", "open", "root"]
    assert result.due == 5 and result.ok == 5


# 2 ── due rule
def test_not_due_units_are_not_selected(w, monkeypatch):
    root = w.ours()
    _root_at(root, _ago(days=1))  # fresh: the root is not due
    ok_3d = _claimed_at(w, root, _ago(days=3))
    failed_25h = _claimed_at(w, root, _ago(hours=25), failed=True)
    failed_2h = _claimed_at(w, root, _ago(hours=2), failed=True)
    open_3d = _open_at(w, root, _ago(days=3))
    open_failed_25h = _open_at(w, root, _ago(hours=25), failed=True)
    _scope(monkeypatch, root)
    calls = Calls(monkeypatch)

    result = rolling.run_rediscovery_tick()

    assert sorted(calls.ids, key=str) == sorted([failed_25h, open_failed_25h], key=str)  # reached
    assert not {ok_3d, failed_2h, open_3d, root.id} & set(calls.ids)
    assert result.due == 2


# 3 ── eligibility
def test_abandoned_deal_units_are_not_selected(w, monkeypatch):
    ours = w.ours()
    live, _ = w.deal()
    dead, eng = w.deal()
    eng.posture = "abandoned"
    w.db.commit()
    expect = set()
    for r in (ours, live):
        expect |= {_claimed_at(w, r, None), _open_at(w, r, None), r.id}
    blocked = {_claimed_at(w, dead, None), _open_at(w, dead, None), dead.id}
    _scope(monkeypatch, ours, live, dead)
    calls = Calls(monkeypatch)

    rolling.run_rediscovery_tick()

    assert set(calls.ids) == expect  # ours and the live deal ran
    assert not blocked & set(calls.ids)


# 4 ── rate limited stops the run
def test_rate_limited_outcome_stops_the_run(w, monkeypatch, caplog):
    root = w.ours()
    _root_at(root, _ago(days=1))
    ids = [_claimed_at(w, root, None) for _ in range(3)]
    _scope(monkeypatch, root)
    calls = Calls(monkeypatch, outcome=runner.UNIT_RATE_LIMITED)

    with caplog.at_level("WARNING"):
        result = rolling.run_rediscovery_tick()

    assert len(calls.log) == 1 and calls.ids[0] in ids  # the first unit WAS reached; nothing after it
    assert result.rate_limited == 1 and result.due == 3 and result.ok == 0
    assert any("rate limited" in r.getMessage() and "2 due" in r.getMessage() for r in caplog.records)


# 5 ── time limit
def test_time_limit_stops_the_run(w, monkeypatch):
    root = w.ours()
    _root_at(root, _ago(days=1))
    for _ in range(3):
        _claimed_at(w, root, None)
    _scope(monkeypatch, root)
    clock = {"t": 0.0}
    monkeypatch.setattr(rolling, "_monotonic", lambda: clock["t"])
    calls = Calls(monkeypatch)
    calls.hook = lambda k, u: clock.__setitem__("t", clock["t"] + 400)

    result = rolling.run_rediscovery_tick()

    assert len(calls.log) == 2  # the first two ran (400 < 600), the third did not
    assert result.out_of_time is True and result.ok == 2 and result.due == 3


# 6 ── slot held by someone else
def test_a_held_slot_skips_claimed_and_root_units_but_not_open_ones(w, monkeypatch):
    root = w.ours()
    claimed = _claimed_at(w, root, None)
    opened = _open_at(w, root, None)
    _scope(monkeypatch, root)
    calls = Calls(monkeypatch)
    assert runner.try_begin_recheck(root.id)
    try:
        result = rolling.run_rediscovery_tick()
        assert calls.log == [("open", opened)]  # the open unit ran
        assert claimed not in calls.ids and root.id not in calls.ids
        assert result.skipped_busy == 2 and result.ok == 1
        assert root.id in runner._recheck_running  # the job did not release a slot it did not take
    finally:
        runner.end_recheck(root.id)
    assert root.id not in runner._recheck_running


# 7 ── slot released when a unit raises
def test_the_slot_taken_is_released_when_the_unit_raises(w, monkeypatch):
    root = w.ours()
    _root_at(root, _ago(days=1))
    c1 = _claimed_at(w, root, None)
    c2 = _claimed_at(w, root, None)
    _scope(monkeypatch, root)
    calls = Calls(monkeypatch)
    held_during = []

    def hook(kind, uid):
        held_during.append(root.id in runner._recheck_running)
        if len(calls.log) == 1:
            raise RuntimeError("unit exploded")

    calls.hook = hook

    result = rolling.run_rediscovery_tick()

    assert set(calls.ids) == {c1, c2}  # the next unit ran after the raise
    assert held_during == [True, True]  # the slot was taken for each
    assert result.errors == 1 and result.ok == 1
    assert root.id not in runner._recheck_running


# 8 ── re-check at unit time
def test_a_unit_refreshed_since_selection_is_skipped(w, monkeypatch):
    root = w.ours()
    _root_at(root, _ago(days=1))
    c1 = _claimed_at(w, root, None)
    c2 = _claimed_at(w, root, None)
    first, second = sorted([c1, c2], key=str)
    _scope(monkeypatch, root)
    calls = Calls(monkeypatch)
    calls.hook = lambda kind, uid: _set(ScopeCandidate, second, "rediscovered_at", datetime.now(timezone.utc), "rediscovery_failed")

    result = rolling.run_rediscovery_tick()

    assert calls.ids == [first]  # the first ran ...
    assert result.skipped == 1 and result.ok == 1 and result.due == 2  # ... the stamped one did not


# 9 ── end to end, real units
def test_end_to_end_stamps_all_three_units_and_the_next_tick_finds_nothing_due(w, monkeypatch):
    root = w.ours()
    domain = _dom("e2e")
    claimed = _claimed_domain(w, root, domain)
    opened = _insert_candidate(w.db, root.id, value=_dom("e2eo"), status="open")
    _seed_ip(w, domain, _ip())
    t, rir = Transport(), _stub_rir(monkeypatch)
    _limiter(monkeypatch, True)
    monkeypatch.setattr(hc, "connector_get", t)
    verified = []

    def collect(db, d):
        verified.append(d)
        return DomainFacts(
            domain=d, ns=(), mx=(), spf_senders=(), spf_includes=(), registrant_org=None,
            registrant_org_folded=None, lookup_errors=(),
        )

    monkeypatch.setattr(runner, "_collect", collect)
    _scope(monkeypatch, root)

    first = rolling.run_rediscovery_tick()

    assert first.due == 3 and first.ok == 3 and first.errors == 0, first
    assert t.calls == 1 and rir == [domain] and verified  # the real units reached their transports
    c, o, r = _row(claimed), _row(opened), _root_row(root.id)
    assert c.rediscovered_at is not None and c.rediscovery_failed is False
    assert o.reverified_at is not None and o.reverify_failed is False
    assert r.rediscovered_at is not None and r.rediscovery_failed is False
    assert root.id not in runner._recheck_running

    second = rolling.run_rediscovery_tick()
    assert second.due == 0 and second.ok == 0


# 9b ── an open unit whose verification pair raises
def test_an_open_unit_whose_pair_raises_is_failed_and_stamped_while_another_is_ok(w, monkeypatch):
    root = w.ours()
    _root_at(root, _ago(days=1))
    _claimed_domain(w, root, _dom("anchor"))
    bad_value, good_value = _dom("badpair"), _dom("goodpair")
    bad = _insert_candidate(w.db, root.id, value=bad_value, status="open")
    good = _insert_candidate(w.db, root.id, value=good_value, status="open")
    seen = []

    def collect(db, domain):
        seen.append(domain)
        if domain == bad_value:
            raise RuntimeError("lookup exploded")
        return DomainFacts(
            domain=domain, ns=(), mx=(), spf_senders=(), spf_includes=(), registrant_org=None,
            registrant_org_folded=None, lookup_errors=(),
        )

    monkeypatch.setattr(runner, "_collect", collect)
    _scope(monkeypatch, root)
    # the claimed anchor is also due (never refreshed); keep it out of this test's counts
    monkeypatch.setattr(runner, "refresh_claimed_domain", lambda cid: runner.UNIT_OK)

    result = rolling.run_rediscovery_tick()

    assert bad_value in seen and good_value in seen  # both pairs were reached
    assert result.failed == 1, result
    b, g = _row(bad), _row(good)
    assert b.reverify_failed is True and b.reverified_at is not None
    assert g.reverify_failed is False and g.reverified_at is not None


# 10 ── scheduler registration
@pytest.fixture
def sched(monkeypatch):
    s = BackgroundScheduler(timezone="UTC")  # never started: jobs stay pending, no thread
    monkeypatch.setattr(scheduler, "_scheduler", s)
    return s


def _cron(job):
    return {f.name: str(f) for f in job.trigger.fields}


def test_rediscovery_tick_is_registered_hourly_at_20(sched):
    scheduler._register_rediscovery_tick()
    job = sched.get_job("rediscovery_tick")
    assert job is not None
    assert job.func is scheduler._run_rediscovery_tick
    f = _cron(job)
    assert (f["minute"], f["hour"], f["day"], f["day_of_week"]) == ("20", "*", "*", "*")
    assert str(job.trigger.timezone) == "UTC"
    assert job.coalesce is True and job.max_instances == 1
    assert job.name == "Org discovery: rolling re-discovery (hourly)"


def test_capture_sweep_is_registered_hourly_at_40(sched):
    scheduler._register_capture_sweep()
    job = sched.get_job("capture_sweep")
    assert job is not None
    assert job.func is scheduler._run_capture_sweep
    f = _cron(job)
    assert (f["minute"], f["hour"], f["day"], f["day_of_week"]) == ("40", "*", "*", "*")
    assert str(job.trigger.timezone) == "UTC"
    assert job.coalesce is True and job.max_instances == 1
    assert job.name == "Automatic page capture (hourly)"


def test_run_wrapper_logs_and_swallows_a_failure(monkeypatch, caplog):
    monkeypatch.setattr(rolling, "run_rediscovery_tick", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    with caplog.at_level("ERROR"):
        scheduler._run_rediscovery_tick()  # must not raise
    assert any("rolling re-discovery failed" in r.getMessage() for r in caplog.records)
