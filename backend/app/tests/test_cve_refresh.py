"""planning#360 part B: the rolling CVE refresh job, its pacing, and the shared
re-score helper. The real selection SQL and the real writers run over real rows;
only the network seams (`_lookup_cve`, `_get_kev_dict`, `enabled_config`), the
clock and the notification dispatch are replaced. `_read_due` is wrapped only to
scope a run to the CVEs THIS test made (the table is shared). Synthetic CVE ids
(CVE-2099-5xxx) and hosts only; no network addresses.

Run with:  backend/scripts/test.sh app/tests/test_cve_refresh.py
"""

import uuid
from datetime import date, datetime, timedelta, timezone

import pytest

from app.core.database import SessionLocal
from app.models.app_settings import AppSetting
from app.models.asset_canonical import AssetCanonical
from app.models.cve_record import CveRecord
from app.models.finding_canonical import FindingCanonical
from app.models.score_history import ScoreHistory
from app.services import connector_instances, cve_refresh, job_runs, nightly_rescore, notification_dispatcher
from app.services import cve_refresh_pacing as pacing_mod
from app.services import scheduler

HOST = "cve-refresh.fabrikam.com"
PREFIX = "CVE-2099-5"
PUB = datetime(2021, 12, 10, 10, 15, tzinfo=timezone.utc)
_PACING_KEYS = (pacing_mod.TIME_LIMIT_KEY, pacing_mod.DUE_BATCH_KEY,
                pacing_mod.REFRESH_INTERVAL_KEY, pacing_mod.FAILED_RETRY_KEY)


def cve(n: int) -> str:
    return f"{PREFIX}{n:03d}"


def _ago(**kw):
    return datetime.now(timezone.utc) - timedelta(**kw)


def _purge(s):
    s.rollback()
    asset_ids = [r[0] for r in s.query(AssetCanonical.id).filter(AssetCanonical.value == HOST)]
    if asset_ids:
        fids = [r[0] for r in s.query(FindingCanonical.id).filter(FindingCanonical.asset_canonical_id.in_(asset_ids))]
        if fids:
            s.query(ScoreHistory).filter(ScoreHistory.finding_canonical_id.in_(fids)).delete(synchronize_session=False)
        s.query(FindingCanonical).filter(FindingCanonical.asset_canonical_id.in_(asset_ids)).delete(
            synchronize_session=False
        )
        s.query(AssetCanonical).filter(AssetCanonical.id.in_(asset_ids)).delete(synchronize_session=False)
    s.query(CveRecord).filter(CveRecord.cve_id.startswith(PREFIX)).delete(synchronize_session=False)
    s.query(AppSetting).filter(AppSetting.key.in_(_PACING_KEYS)).delete(synchronize_session=False)
    s.commit()


@pytest.fixture
def db():
    s = SessionLocal()
    _purge(s)
    yield s
    s.rollback()
    _purge(s)
    s.close()


def _findings(db, specs):
    """specs: [(cve_id, kwargs)] -> {cve_id: finding id}. One asset, one finding each."""
    now = datetime.now(timezone.utc)
    asset = db.query(AssetCanonical).filter(AssetCanonical.value == HOST).first()
    if asset is None:
        asset = AssetCanonical(
            id=uuid.uuid4(), asset_type="domain", value=HOST, first_seen_at=now, last_seen_at=now,
            ignored=False, tags=[],
        )
        db.add(asset)
        db.flush()
    ids = {}
    for cid, kw in specs:
        f = FindingCanonical(
            id=uuid.uuid4(), asset_canonical_id=asset.id, finding_type="cve", source="test",
            fingerprint=f"fp-{uuid.uuid4().hex[:8]}", severity="high", title=f"{cid} exposed",
            state=kw.pop("state", "open"), category="vulnerability", cve_id=cid, first_seen_at=now,
            last_seen_at=now, detail={}, tags=[], **kw,
        )
        db.add(f)
        ids[cid] = f.id
    db.commit()
    return ids


def _record(db, cid, at, failed=False, published=None):
    db.add(CveRecord(cve_id=cid, refreshed_at=at, refresh_failed=failed, published_at=published,
                     published_source="vulncheck_nvd2" if published else None))
    db.commit()


def _row(db, cid):
    db.expire_all()
    return db.get(CveRecord, cid)


def _mine(ids):
    return [c for c in ids if c.startswith(PREFIX)]


def _sig():
    return {"published_at": PUB, "vulncheck_kev_date_added": date(2022, 1, 5), "vulncheck_kev": False,
            "has_exploit": False, "exploit_count": 0, "exploit_types": [], "ransomware_use": False,
            "canary_detected": False, "intel": {}}


@pytest.fixture
def env(monkeypatch):
    """No network: a VulnCheck key is configured, CISA lists nothing, the tick sees only this
    test's CVEs, and dispatch is a recording spy."""
    e = type("Env", (), {})()
    e.key = {"api_key": "synthetic-key"}
    e.kev = {"CVE-2099-0000": "2024-01-01"}  # non-empty: the feed "worked"
    e.lookups = []
    e.results = {}  # cve -> sig dict | None (default: a plain success)
    e.dispatched = []
    e.now_scope = None

    monkeypatch.setattr(connector_instances, "enabled_config", lambda db, t: e.key)
    monkeypatch.setattr(cve_refresh, "_get_kev_dict", lambda: e.kev)

    def lookup(cid, headers, *, fresh=False):
        e.lookups.append((cid, fresh, dict(headers)))
        return e.results.get(cid, _sig())

    monkeypatch.setattr(cve_refresh, "_lookup_cve", lookup)
    monkeypatch.setattr(notification_dispatcher, "dispatch_promotions", lambda p: e.dispatched.append(list(p)))
    real = cve_refresh._read_due
    monkeypatch.setattr(cve_refresh, "_read_due", lambda db, now, pacing: _mine(real(db, now, pacing)))
    e.lookup_ids = lambda: [x[0] for x in e.lookups]
    return e


# ── due selection (the real SQL) ────────────────────────────────────────────────

def test_due_selection_and_order(db):
    specs = [(cve(i), {}) for i in (1, 2, 3, 4, 5, 7)] + [("cve-2099-5006", {}), (cve(8), {"state": "resolved"})]
    _findings(db, specs)
    _record(db, cve(2), _ago(hours=1))  # fresh success: not due
    _record(db, cve(3), _ago(hours=25), published=PUB)  # success past the interval: due
    _record(db, cve(4), _ago(hours=1), failed=True)  # failure inside the retry window: not due
    _record(db, cve(5), _ago(hours=7), failed=True)  # failure past the retry: due
    _record(db, cve(6), _ago(hours=1))  # keyed by the upper-case id; the finding carries it lower-case
    db.add(CveRecord(cve_id=cve(7)))  # a row never stamped: due
    db.commit()
    got = _mine(cve_refresh._read_due(db, datetime.now(timezone.utc), pacing_mod.read(db)))
    assert cve(6) not in got, "the lower-case finding id maps to the upper-case row"
    assert cve(1) in got, "no row at all is due"
    assert cve(8) in got, "a resolved finding's CVE is still considered"
    assert set(got) == {cve(1), cve(3), cve(5), cve(7), cve(8)}
    # never-stamped first (by id), then the oldest attempt
    assert got == [cve(1), cve(7), cve(8), cve(3), cve(5)]


def test_due_batch_limits_the_read(db):
    _findings(db, [(cve(i), {}) for i in range(1, 15)])
    p = pacing_mod.CveRefreshPacing(60, 10, timedelta(hours=24), timedelta(hours=6))
    assert len(cve_refresh._read_due(db, datetime.now(timezone.utc), p)) == 10  # 14+ are due: capped at the batch


def test_due_interval_comes_from_pacing(db):
    _findings(db, [(cve(1), {})])
    _record(db, cve(1), _ago(minutes=61))
    now = datetime.now(timezone.utc)
    day = pacing_mod.CveRefreshPacing(60, 5000, timedelta(hours=24), timedelta(hours=6))
    hour = pacing_mod.CveRefreshPacing(60, 5000, timedelta(hours=1), timedelta(hours=1))
    assert cve(1) not in cve_refresh._read_due(db, now, day)
    assert cve(1) in cve_refresh._read_due(db, now, hour)


# ── a refresh ───────────────────────────────────────────────────────────────────

def test_refresh_writes_dates_mirrors_cisa_and_asks_for_fresh(db, env):
    ids = _findings(db, [(cve(1), {"cvss_score": 5.0, "kev": False})])
    env.kev = {cve(1): "2023-05-06"}
    env.results[cve(1)] = _sig()
    r = cve_refresh.run_cve_refresh_tick()
    assert env.lookups, "the lookup was reached"
    assert env.lookups[0][0] == cve(1) and env.lookups[0][1] is True, "fresh=True is passed"
    assert env.lookups[0][2]["Authorization"] == "Bearer synthetic-key"
    row = _row(db, cve(1))
    assert row.published_at == PUB and row.vulncheck_kev_date_added == date(2022, 1, 5)
    assert row.refreshed_at is not None and row.refresh_failed is False
    db.expire_all()
    f = db.get(FindingCanonical, ids[cve(1)])
    assert f.kev is True and str(f.kev_date_added)[:10] == "2023-05-06"
    assert (r.due, r.refreshed, r.failed, r.errors, r.kev_rows_set) == (1, 1, 0, 0, 1)
    assert r.vulncheck_configured and r.cisa_feed_ok and not r.out_of_time and not r.stopped_on_lookup


def test_newly_kev_cve_is_rescored_and_promotion_dispatched_except_excluded(db, env):
    ids = _findings(db, [
        (cve(1), {"cvss_score": 5.0, "kev": False}),
        (cve(2), {"cvss_score": 5.0, "kev": False, "verification": "rejected_shared_infra"}),
    ])
    nightly_rescore.rescore_and_notify(db, set(ids.values()), datetime.now(timezone.utc))  # baseline
    db.expire_all()
    base = {c: db.get(FindingCanonical, i) for c, i in ids.items()}
    assert {f.risk_band for f in base.values()} == {"elevated"}
    before = {c: f.risk_score for c, f in base.items()}
    hist = lambda i: db.query(ScoreHistory).filter(ScoreHistory.finding_canonical_id == i).count()
    assert [hist(i) for i in ids.values()] == [1, 1]
    env.dispatched.clear()

    env.kev = {cve(1): "2024-02-02", cve(2): "2024-02-02"}
    r = cve_refresh.run_cve_refresh_tick()

    db.expire_all()
    for c, i in ids.items():
        f = db.get(FindingCanonical, i)
        assert f.risk_band == "imminent_compromise", c
        assert f.risk_score != before[c], c
        assert hist(i) == 2, "a score_history row was written"
    sent = {p.finding_canonical_id for call in env.dispatched for p in call}
    assert ids[cve(1)] in sent, "the ordinary promotion was dispatched"
    assert ids[cve(2)] not in sent, "the excluded verification was re-scored but not dispatched"
    assert (r.rescored, r.promotions) == (2, 2)


def test_rescore_failure_is_counted_and_the_tick_returns(db, env, monkeypatch):
    _findings(db, [(cve(1), {"cvss_score": 5.0, "kev": False})])
    env.kev = {cve(1): "2024-02-02"}

    def boom(*a, **k):
        raise RuntimeError("scorer down")

    monkeypatch.setattr(nightly_rescore, "rescore_and_notify", boom)
    r = cve_refresh.run_cve_refresh_tick()
    assert r.errors == 1 and r.rescored == 0 and r.refreshed == 1
    assert _row(db, cve(1)).refreshed_at is not None, "the refresh itself stayed committed"


# ── VulnCheck failures ──────────────────────────────────────────────────────────

def test_failure_marks_failed_and_keeps_dates(db, env):
    _findings(db, [(cve(1), {})])
    _record(db, cve(1), _ago(hours=30), published=PUB)
    env.results[cve(1)] = None
    r = cve_refresh.run_cve_refresh_tick()
    assert env.lookups, "the lookup was reached"
    row = _row(db, cve(1))
    assert row.refresh_failed is True and row.published_at == PUB and row.published_source == "vulncheck_nvd2"
    assert row.refreshed_at > _ago(minutes=1)
    assert (r.failed, r.refreshed) == (1, 0)


def test_five_consecutive_failures_stop_the_run(db, env):
    _findings(db, [(cve(i), {}) for i in range(1, 8)])
    for i in range(1, 6):
        env.results[cve(i)] = None
    r = cve_refresh.run_cve_refresh_tick()
    assert env.lookup_ids() == [cve(i) for i in range(1, 6)], "stopped after the fifth"
    assert r.stopped_on_lookup and r.failed == 5 and r.refreshed == 0
    assert _row(db, cve(6)) is None and _row(db, cve(7)) is None, "the rest are untouched"
    assert all(_row(db, cve(i)).refresh_failed for i in range(1, 6))
    assert job_runs.cve_refresh_outcome(r).finish_reason == "lookup_failures"


def test_a_success_resets_the_failure_streak(db, env):
    _findings(db, [(cve(i), {}) for i in range(1, 10)])
    for i in (1, 2, 3, 4, 6, 7, 8, 9):
        env.results[cve(i)] = None
    r = cve_refresh.run_cve_refresh_tick()
    assert len(env.lookups) == 9, "4 failures, a success, 4 failures never reach 5 in a row"
    assert not r.stopped_on_lookup and (r.failed, r.refreshed) == (8, 1)
    assert job_runs.cve_refresh_outcome(r).finish_reason == "done"


def test_no_vulncheck_key_still_mirrors_cisa_and_stamps_without_dates(db, env):
    ids = _findings(db, [(cve(1), {"cvss_score": 5.0, "kev": False})])
    env.key = None
    env.kev = {cve(1): "2024-02-02"}
    r = cve_refresh.run_cve_refresh_tick()
    assert not env.lookups, "no VulnCheck call without a key"
    row = _row(db, cve(1))
    assert row is not None and row.refreshed_at is not None and row.refresh_failed is False
    assert row.published_at is None and row.vulncheck_kev_date_added is None
    db.expire_all()
    assert db.get(FindingCanonical, ids[cve(1)]).kev is True, "the CISA mirror still ran"
    assert not r.vulncheck_configured and r.refreshed == 1 and r.failed == 0 and r.kev_rows_set == 1


def test_keyless_stamp_never_touches_stored_dates(db, env):
    _findings(db, [(cve(1), {})])
    _record(db, cve(1), _ago(hours=30), failed=True, published=PUB)
    env.key = None
    cve_refresh.run_cve_refresh_tick()
    row = _row(db, cve(1))
    assert row.published_at == PUB and row.refresh_failed is False and row.refreshed_at > _ago(minutes=1)


def test_cisa_feed_ok_follows_the_dict(db, env):
    _findings(db, [(cve(1), {})])
    env.kev = {}
    r = cve_refresh.run_cve_refresh_tick()
    assert env.lookups and not r.cisa_feed_ok


# ── time limit and unit isolation ───────────────────────────────────────────────

def test_time_limit_stops_before_the_next_cve(db, env, monkeypatch):
    _findings(db, [(cve(i), {}) for i in range(1, 5)])
    clock = iter([0, 0, 0, 10_000, 10_000, 10_000])  # start, check 1, check 2, check 3 (over the limit)
    monkeypatch.setattr(cve_refresh, "_monotonic", lambda: next(clock))
    r = cve_refresh.run_cve_refresh_tick()
    assert r.out_of_time and r.refreshed == 2 and r.due == 4
    assert env.lookup_ids() == [cve(1), cve(2)]
    assert _row(db, cve(3)) is None and _row(db, cve(4)) is None
    assert job_runs.cve_refresh_outcome(r).finish_reason == "time_limit"


def test_an_exception_in_one_unit_rolls_back_that_unit_only(db, env, monkeypatch):
    ids = _findings(db, [(cve(1), {"cvss_score": 5.0, "kev": False}), (cve(2), {"cvss_score": 5.0, "kev": False})])
    env.kev = {cve(1): "2024-02-02", cve(2): "2024-02-02"}
    real = cve_refresh.mirror_signals

    def flaky(db_, signals):
        if cve(1) in signals:
            raise RuntimeError("write failed")
        return real(db_, signals)

    monkeypatch.setattr(cve_refresh, "mirror_signals", flaky)
    r = cve_refresh.run_cve_refresh_tick()
    assert env.lookup_ids() == [cve(1), cve(2)], "the failing unit was reached, then the next ran"
    assert r.errors == 1 and r.refreshed == 1
    db.expire_all()
    assert _row(db, cve(1)) is None, "the failed unit left no record"
    assert db.get(FindingCanonical, ids[cve(1)]).kev is False, "its flushed CISA mirror was rolled back"
    assert _row(db, cve(2)).refreshed_at is not None
    assert db.get(FindingCanonical, ids[cve(2)]).kev is True


# ── outcome ─────────────────────────────────────────────────────────────────────

def test_outcome_counts_carry_every_field():
    r = cve_refresh.CveRefreshResult(due=3, refreshed=1, failed=1, errors=1, kev_rows_set=2, rescored=4,
                                     promotions=1, vulncheck_configured=True, cisa_feed_ok=False)
    o = job_runs.cve_refresh_outcome(r)
    assert o.finish_reason == "done" and o.items_selected == 3
    assert o.counts == {"due": 3, "refreshed": 1, "failed": 1, "errors": 1, "kev_rows_set": 2, "rescored": 4,
                        "promotions": 1, "vulncheck_configured": 1, "cisa_feed_ok": 0, "out_of_time": 0,
                        "stopped_on_lookup": 0}


def test_wrapper_records_the_run(db, monkeypatch):
    from app.models.job_run import JobRun
    res = cve_refresh.CveRefreshResult(due=2, refreshed=2)
    monkeypatch.setattr(cve_refresh, "run_cve_refresh_tick", lambda: res)
    with SessionLocal() as s:
        before = s.query(JobRun).filter(JobRun.job == "cve_refresh").count()
    scheduler._run_cve_refresh()
    with SessionLocal() as s:
        rows = s.query(JobRun).filter(JobRun.job == "cve_refresh").order_by(JobRun.started_at.desc()).all()
        assert len(rows) == before + 1 and rows[0].finish_reason == "done" and rows[0].items_selected == 2
        s.query(JobRun).filter(JobRun.id == rows[0].id).delete(synchronize_session=False)
        s.commit()


# ── pacing ──────────────────────────────────────────────────────────────────────

def _set(db, key, value):
    db.add(AppSetting(key=key, value=value))
    db.commit()


def test_pacing_defaults(db):
    p = pacing_mod.read(db)
    assert (p.time_limit_s, p.due_batch) == (300, 500)
    assert (p.refresh_interval, p.failed_retry_after) == (timedelta(hours=24), timedelta(hours=6))


@pytest.mark.parametrize("key,bad", [
    (pacing_mod.TIME_LIMIT_KEY, "59"), (pacing_mod.TIME_LIMIT_KEY, "3001"), (pacing_mod.TIME_LIMIT_KEY, "x"),
    (pacing_mod.DUE_BATCH_KEY, "9"), (pacing_mod.DUE_BATCH_KEY, "5001"),
    (pacing_mod.REFRESH_INTERVAL_KEY, "0"), (pacing_mod.REFRESH_INTERVAL_KEY, "721"),
    (pacing_mod.FAILED_RETRY_KEY, "0"), (pacing_mod.FAILED_RETRY_KEY, "721"),
])
def test_out_of_range_stored_value_falls_back_to_default(db, key, bad):
    _set(db, key, bad)
    p = pacing_mod.read(db)
    assert (p.time_limit_s, p.due_batch) == (300, 500)
    assert (p.refresh_interval, p.failed_retry_after) == (timedelta(hours=24), timedelta(hours=6))


def test_in_range_stored_values_apply_and_failed_retry_is_capped_at_the_interval(db):
    _set(db, pacing_mod.TIME_LIMIT_KEY, "120")
    _set(db, pacing_mod.DUE_BATCH_KEY, "40")
    _set(db, pacing_mod.REFRESH_INTERVAL_KEY, "3")
    _set(db, pacing_mod.FAILED_RETRY_KEY, "10")
    p = pacing_mod.read(db)
    assert (p.time_limit_s, p.due_batch) == (120, 40)
    assert p.refresh_interval == timedelta(hours=3) and p.failed_retry_after == timedelta(hours=3)
