"""Job run history (planning#329): outcome mappers, recording wrappers, purge,
missed-slot status, scheduler registration. Real constellus_test DB; synthetic data.

Run with:  scripts/test.sh app/tests/test_job_runs.py
"""
import inspect
import logging
import re
from datetime import datetime, timedelta, timezone

import pytest
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

from app.core.database import SessionLocal
from app.models.app_settings import AppSetting
from app.models.job_run import JOB_RUN_FINISH_REASONS, JobRun
from app.services.cloud_ranges import RefreshResult
from app.services import app_settings, job_runs, page_capture, scheduler
from app.services.org_discovery import rolling
from app.services.org_discovery.rolling import RollingResult
from app.services.page_capture import SweepResult
from app.services.page_capture import TickResult as PageCaptureTick
from app.services.ct_refresher import TickResult as CtRefresherTick
from app.services.tenancy_enricher import TickResult as TenancyEnricherTick
from app.services.tenancy_tls import TickResult as TenancyTlsTick
from app.services import tenancy_tls

UTC = timezone.utc


def _wipe():
    with SessionLocal() as s:
        s.query(JobRun).delete(synchronize_session=False)
        s.commit()


@pytest.fixture(autouse=True)
def clean():
    _wipe()
    yield
    _wipe()


def _rows(job=None):
    with SessionLocal() as s:
        q = s.query(JobRun)
        if job:
            q = q.filter(JobRun.job == job)
        rows = q.order_by(JobRun.started_at).all()
        s.expunge_all()
        return rows


def _insert(job, started, reason="done"):
    with SessionLocal() as s:
        s.add(JobRun(job=job, started_at=started, finished_at=started + timedelta(minutes=1),
                     finish_reason=reason, items_selected=0, counts={}))
        s.commit()


# 1 -- mappers
@pytest.mark.parametrize("kw,reason", [
    ({"not_configured": True}, "not_configured"),
    ({"stopped_on_lookup": True}, "lookup_failures"),
    ({"out_of_time": True}, "time_limit"),
    ({}, "done"),
])
def test_capture_outcome(kw, reason):
    o = job_runs.capture_outcome(SweepResult(candidates=5, queued=2, budget=1, skipped=1, errors=1, **kw))
    assert o.finish_reason == reason
    assert o.items_selected == 5
    assert o.counts == {"candidates": 5, "queued": 2, "budget": 1, "skipped": 1, "errors": 1}


@pytest.mark.parametrize("kw,reason", [
    ({"rate_limited": 1}, "rate_limited"),
    ({"out_of_time": True}, "time_limit"),
    ({"rate_limited": 1, "out_of_time": True}, "rate_limited"),
    ({}, "done"),
])
def test_rediscovery_outcome(kw, reason):
    o = job_runs.rediscovery_outcome(RollingResult(due=7, ok=3, failed=2, skipped_busy=1, skipped=1, errors=1, **kw))
    assert o.finish_reason == reason
    assert o.items_selected == 7
    assert set(o.counts) == {"due", "ok", "failed", "rate_limited", "skipped_busy", "skipped", "errors"}
    assert o.counts["due"] == 7 and o.counts["ok"] == 3 and o.counts["failed"] == 2
    assert o.counts["rate_limited"] == kw.get("rate_limited", 0)


def test_int_outcome():
    assert job_runs.int_outcome("deleted")(3) == job_runs.RunOutcome("done", 3, {"deleted": 3})


_MAPPER_CASES = [
    ("epss", job_runs.epss_outcome({"upserted": 5, "pruned": 2}), "done", 5, {"upserted": 5, "pruned": 2}),
    ("cpe", job_runs.cpe_index_outcome({"seeded": 4, "delta": 3, "days_done": 5, "days_left": 0, "stopped": "done"}),
     "done", 7, {"seeded": 4, "delta": 3, "days_done": 5, "days_left": 0}),
    ("cpe_time_limit",
     job_runs.cpe_index_outcome({"seeded": 0, "delta": 9, "days_done": 2, "days_left": 6, "stopped": "time_limit"}),
     "time_limit", 9, {"seeded": 0, "delta": 9, "days_done": 2, "days_left": 6}),
    ("cpe_source_refused",
     job_runs.cpe_index_outcome({"seeded": 0, "delta": 1, "days_done": 1, "days_left": 3, "stopped": "source_refused"}),
     "source_refused", 1, {"seeded": 0, "delta": 1, "days_done": 1, "days_left": 3}),
    ("cpe_not_configured",
     job_runs.cpe_index_outcome({"seeded": 0, "delta": 0, "days_done": 0, "days_left": 0, "stopped": "not_configured"}),
     "not_configured", 0, {"seeded": 0, "delta": 0, "days_done": 0, "days_left": 0}),
    ("cloud_changed",
     job_runs.cloud_ranges_outcome(RefreshResult(ok=True, changed=True, record_count=12, dataset_sha256="x")),
     "done", 12, {"changed": 1, "record_count": 12}),
    ("cloud_unchanged",
     job_runs.cloud_ranges_outcome(RefreshResult(ok=True, changed=False, record_count=12, dataset_sha256="x")),
     "done", 0, {"changed": 0, "record_count": 12}),
    ("partition",
     job_runs.partition_outcome({"a": {"created": ["p1"], "dropped": [], "retained": 3},
                                 "b": {"created": [], "dropped": ["p0", "p9"], "retained": 2}}),
     "done", 3, {"created": 1, "dropped": 2, "retained": 5}),
    ("hygiene",
     job_runs.hygiene_outcome({"scored": 9, "excluded": 1, "deleted": 2, "history_rows": 4, "elapsed_ms": 55}),
     "done", 9, {"scored": 9, "excluded": 1, "deleted": 2, "history_rows": 4}),
    ("rescore",
     job_runs.rescore_outcome({"rescored": 8, "history_rows": 3, "promotions": 1, "elapsed_ms": 70}),
     "done", 8, {"rescored": 8, "history_rows": 3, "promotions": 1}),
    ("reaper", job_runs.reaper_outcome({"startup": True, "runs": 2, "ingest_runs": 1}),
     "done", 3, {"startup": 1, "runs": 2, "ingest_runs": 1}),
    ("llm_none", job_runs.llm_models_outcome(None), "not_configured", 0, {}),
    ("llm_7", job_runs.llm_models_outcome(7), "done", 7, {"models": 7}),
]


@pytest.mark.parametrize("name,o,reason,items,counts", _MAPPER_CASES, ids=[c[0] for c in _MAPPER_CASES])
def test_new_mappers(name, o, reason, items, counts):
    assert o.finish_reason == reason and o.finish_reason in JOB_RUN_FINISH_REASONS
    assert o.items_selected == items
    assert o.counts == counts
    assert all(isinstance(v, int) for v in o.counts.values())


def test_int_outcome_reason_is_valid():
    assert job_runs.int_outcome("x")(0).finish_reason in JOB_RUN_FINISH_REASONS


# 2 -- capture wrapper
@pytest.mark.parametrize("kw,reason", [
    ({"not_configured": True}, "not_configured"),
    ({"stopped_on_lookup": True}, "lookup_failures"),
    ({"out_of_time": True}, "time_limit"),
    ({}, "done"),
])
def test_capture_wrapper_records_each_variant(monkeypatch, kw, reason):
    called = []
    res = SweepResult(candidates=4, queued=3, budget=1, **kw)
    monkeypatch.setattr(page_capture, "run_automatic_sweep", lambda: called.append(1) or res)
    scheduler._run_capture_sweep()
    assert called == [1]
    rows = _rows()
    assert len(rows) == 1
    r = rows[0]
    assert r.job == "capture_sweep" and r.finish_reason == reason
    assert r.items_selected == 4 and r.counts["queued"] == 3 and r.error is None
    assert r.started_at <= r.finished_at


# 3 -- rediscovery wrapper
@pytest.mark.parametrize("kw,reason", [
    ({"rate_limited": 1}, "rate_limited"),
    ({"out_of_time": True}, "time_limit"),
    ({}, "done"),
])
def test_rediscovery_wrapper_records_each_variant(monkeypatch, kw, reason):
    called = []
    res = RollingResult(due=6, ok=2, **kw)
    monkeypatch.setattr(rolling, "run_rediscovery_tick", lambda: called.append(1) or res)
    scheduler._run_rediscovery_tick()
    assert called == [1]
    rows = _rows()
    assert len(rows) == 1
    r = rows[0]
    assert r.job == "rediscovery_tick" and r.finish_reason == reason
    assert r.items_selected == 6 and r.counts["ok"] == 2
    assert r.started_at <= r.finished_at


# 4 -- job raising
def test_failing_job_is_recorded_as_error_and_not_raised(monkeypatch, caplog):
    called = []

    def boom():
        called.append(1)
        raise RuntimeError("secret https://example.invalid/?key=abc")

    monkeypatch.setattr(page_capture, "run_automatic_sweep", boom)
    with caplog.at_level("ERROR"):
        scheduler._run_capture_sweep()
    assert called == [1]
    assert any("Automatic page capture failed" in r.getMessage() for r in caplog.records)
    rows = _rows()
    assert len(rows) == 1
    r = rows[0]
    assert r.finish_reason == "error" and r.error == "RuntimeError"
    assert r.items_selected == 0 and r.counts == {}
    assert "secret" not in (r.error or "")


# 5 -- recording failure never fails the run
class _CommitFails:
    def __init__(self):
        self.closed = False
        self.rolled_back = False

    def add(self, _):
        pass

    def commit(self):
        raise RuntimeError("db down")

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


def _run_with(monkeypatch, caplog, factory=None, to_outcome=None):
    called = []
    if factory is not None:
        monkeypatch.setattr(job_runs, "SessionLocal", factory)
    with caplog.at_level("WARNING"):
        out = job_runs.run_recorded(
            "capture_sweep", lambda: called.append(1) or "result",
            to_outcome or (lambda r: job_runs.RunOutcome("done", 0, {})),
        )
    assert called == [1]  # the job WAS called
    assert out == "result"
    assert any("recording a capture_sweep run failed" in r.getMessage() for r in caplog.records)
    assert _rows() == []


def test_commit_failure_does_not_fail_the_run(monkeypatch, caplog):
    sessions = []

    def factory():
        s = _CommitFails()
        sessions.append(s)
        return s

    _run_with(monkeypatch, caplog, factory)
    assert len(sessions) == 1 and sessions[0].rolled_back and sessions[0].closed


def test_session_construction_failure_does_not_fail_the_run(monkeypatch, caplog):
    def factory():
        raise RuntimeError("no pool")

    _run_with(monkeypatch, caplog, factory)


def test_to_outcome_failure_does_not_fail_the_run(monkeypatch, caplog):
    def bad(_):
        raise ValueError("mapper bug")

    _run_with(monkeypatch, caplog, to_outcome=bad)


# 6 -- purge
@pytest.fixture
def hset():
    def _put(v):
        with SessionLocal() as s:
            app_settings.set_value(s, job_runs.RUN_HISTORY_DAYS_KEY, str(v))
    yield _put
    with SessionLocal() as s:
        s.query(AppSetting).filter(AppSetting.key == job_runs.RUN_HISTORY_DAYS_KEY).delete(synchronize_session=False)
        s.commit()


NOW = datetime(2026, 11, 8, 15, 5, tzinfo=UTC)


def _purge(now=NOW):
    with SessionLocal() as s:
        n = job_runs.purge(s, now=now)
        s.commit()
        return n


def test_purge_deletes_only_older_than_retention(hset):
    hset(30)
    _insert("capture_sweep", NOW - timedelta(days=31))
    _insert("capture_sweep", NOW - timedelta(days=29))
    _insert("rediscovery_tick", NOW - timedelta(days=30))  # exactly the cutoff: kept (< is strict)
    assert len(_rows()) == 3
    assert _purge() == 1
    left = _rows()
    assert len(left) == 2
    assert all(r.started_at >= NOW - timedelta(days=30) for r in left)


@pytest.mark.parametrize("bad", ["abc", 6, 366, 0])
def test_purge_falls_back_to_90_on_bad_setting(hset, bad):
    hset(bad)
    with SessionLocal() as s:
        assert job_runs.run_history_days(s) == 90
    _insert("capture_sweep", NOW - timedelta(days=91))
    _insert("capture_sweep", NOW - timedelta(days=89))
    assert _purge() == 1
    assert len(_rows()) == 1


def test_purge_default_and_valid_setting(hset):
    with SessionLocal() as s:
        assert job_runs.run_history_days(s) == 90
    hset(30)
    with SessionLocal() as s:
        assert job_runs.run_history_days(s) == 30


def test_purge_wrapper_commits_and_records_itself(hset):
    hset(90)
    _insert("capture_sweep", job_runs._now() - timedelta(days=400))
    scheduler._run_job_run_purge()
    assert _rows("capture_sweep") == []
    r = _rows("job_run_purger")
    assert len(r) == 1 and r[0].finish_reason == "done" and r[0].counts == {"deleted": 1}


# 7 -- status
def _st(now=NOW, hours=24):
    with SessionLocal() as s:
        return {x.job: x for x in job_runs.status(s, now=now, hours=hours)}


def _h(day, hour, minute):
    return datetime(2026, 11, day, hour, minute, tzinfo=UTC)


def test_status_no_rows():
    st = _st()
    assert list(st) == list(job_runs.CADENCE)
    for x in st.values():
        assert x.last_run is None and x.recorded_since is None and x.missed_slots == []


def test_status_reports_missing_slot_and_not_covered_ones():
    # now 15:05; capture slots :40: judged slots end at <=15:05 -> last judged 13:40 (ends 14:40)
    for hr in (8, 9, 10, 12, 13):  # 11:40 missing
        _insert("capture_sweep", _h(8, hr, 40))
    st = _st(hours=6)  # window start 09:05 -> first slot 09:40
    assert st["capture_sweep"].missed_slots == [_h(8, 11, 40)]  # 14:40 not judged yet


def test_status_exact_judging():
    for hr in (9, 10, 12, 13):
        _insert("capture_sweep", _h(8, hr, 40))
    st = _st(hours=6)
    # 14:40 slot ends at 15:40 > now -> not judged; 11:40 missing
    assert st["capture_sweep"].missed_slots == [_h(8, 11, 40)]
    assert st["capture_sweep"].last_run.started_at == _h(8, 13, 40)
    assert st["capture_sweep"].recorded_since == _h(8, 9, 40)


def test_status_current_slot_not_judged_but_finished_slot_is():
    _insert("capture_sweep", _h(8, 13, 40))
    # now 14:50: slot 13:40 ended 14:40 and is covered; slot 14:40 still running
    assert _st(now=_h(8, 14, 50), hours=1)["capture_sweep"].missed_slots == []
    # no row for 14:40, now 15:45: 14:40 slot over (15:40 <= 15:45) -> missed
    assert _st(now=_h(8, 15, 45), hours=2)["capture_sweep"].missed_slots == [_h(8, 14, 40)]


def test_status_slots_before_recorded_since_not_reported():
    _insert("capture_sweep", _h(8, 12, 40))
    _insert("capture_sweep", _h(8, 13, 40))
    st = _st(hours=24)
    assert st["capture_sweep"].missed_slots == []  # earlier slots predate the record
    assert st["capture_sweep"].recorded_since == _h(8, 12, 40)


def test_status_hours_bounds_the_window():
    _insert("capture_sweep", _h(8, 1, 40))
    _insert("capture_sweep", _h(8, 13, 40))  # slots 02:40..12:40 missing
    wide = _st(hours=24)["capture_sweep"].missed_slots
    narrow = _st(hours=3)["capture_sweep"].missed_slots  # window start 12:05 -> 12:40 only
    assert wide[0] == _h(8, 2, 40) and _h(8, 12, 40) in wide and len(wide) == 11
    assert narrow == [_h(8, 12, 40)]


def test_status_late_start_within_its_hour_covers_the_slot():
    _insert("capture_sweep", _h(8, 11, 40))
    _insert("capture_sweep", _h(8, 12, 52))  # started late
    _insert("capture_sweep", _h(8, 13, 40))
    assert _st(hours=6)["capture_sweep"].missed_slots == []
    # control: without the :52 row the 12:40 slot is missed
    _wipe()
    _insert("capture_sweep", _h(8, 11, 40))
    _insert("capture_sweep", _h(8, 13, 40))
    assert _st(hours=6)["capture_sweep"].missed_slots == [_h(8, 12, 40)]


def test_status_early_start_covers_the_previous_slot_not_the_next():
    # A run at 12:39 for a :40 cadence started within the hour after 11:40, so
    # it covers 11:40; 12:40 is still open and, once its hour ends, missed.
    _insert("capture_sweep", _h(8, 12, 39))
    st = _st(now=_h(8, 14, 5), hours=3)["capture_sweep"]
    assert st.missed_slots == [_h(8, 12, 40)]
    assert st.recorded_since == _h(8, 12, 39)


def test_status_jobs_are_independent():
    _insert("rediscovery_tick", _h(8, 13, 20))
    st = _st(hours=3)
    assert st["capture_sweep"].last_run is None and st["capture_sweep"].missed_slots == []
    assert st["rediscovery_tick"].last_run.job == "rediscovery_tick"


def test_cadence_validation():
    for build in (lambda: job_runs.hourly_at(60), lambda: job_runs.daily_at(24),
                  lambda: job_runs.every(hours=0),
                  lambda: job_runs.Cadence("interval", minute=5, every=timedelta(hours=1))):
        with pytest.raises(ValueError):
            build()
    assert job_runs.every(hours=24).period == timedelta(hours=24)
    assert job_runs.daily_at(3).period == timedelta(days=1)
    assert job_runs.hourly_at(5).to_dict() == {"kind": "hourly_at", "minute": 5, "hour": None, "every_seconds": None}
    assert job_runs.daily_at(3).to_dict() == {"kind": "daily_at", "minute": 0, "hour": 3, "every_seconds": None}
    assert job_runs.every(hours=12).to_dict() == {"kind": "interval", "minute": None, "hour": None,
                                                  "every_seconds": 43200}


def test_cadence_table_shape():
    assert all(isinstance(c, job_runs.Cadence) for c in job_runs.CADENCE.values())
    hourly = [c.minute for c in job_runs.CADENCE.values() if c.kind == "hourly_at"]
    assert sorted(hourly) == [5, 20, 40] and len(set(hourly)) == 3


def test_daily_missed_night_shows_after_its_hour():
    _insert("nightly_rescore", _h(5, 3, 0))
    _insert("nightly_rescore", _h(6, 3, 0))
    assert _st(now=_h(7, 3, 30), hours=72)["nightly_rescore"].missed_slots == []
    assert _st(now=_h(7, 4, 0), hours=72)["nightly_rescore"].missed_slots == [_h(7, 3, 0)]


def test_daily_late_start_within_the_hour_covers():
    _insert("nightly_rescore", _h(6, 3, 0))
    _insert("nightly_rescore", _h(7, 3, 40))
    assert _st(now=_h(7, 12, 0), hours=48)["nightly_rescore"].missed_slots == []
    _wipe()
    _insert("nightly_rescore", _h(6, 3, 0))
    _insert("nightly_rescore", _h(7, 4, 10))
    assert _st(now=_h(7, 12, 0), hours=48)["nightly_rescore"].missed_slots == [_h(7, 3, 0)]


def test_daily_first_record_outside_its_hour_does_not_flag_the_slot_before():
    _insert("nightly_rescore", _h(6, 10, 0))
    assert _st(now=_h(7, 2, 0), hours=48)["nightly_rescore"].missed_slots == []
    assert _st(now=_h(7, 4, 0), hours=48)["nightly_rescore"].missed_slots == [_h(7, 3, 0)]


def test_daily_window_bounds():
    _insert("nightly_rescore", _h(3, 3, 0))
    assert _st(now=_h(8, 15, 5), hours=24)["nightly_rescore"].missed_slots == [_h(8, 3, 0)]
    assert _st(now=_h(8, 15, 5), hours=72)["nightly_rescore"].missed_slots == [_h(6, 3, 0), _h(7, 3, 0), _h(8, 3, 0)]


def test_interval_on_time_runs_have_no_missed():
    for d, m in ((5, 0), (6, 2), (7, 5)):
        _insert("cpe_index_refresher", _h(d, 10, m))
    assert _st(now=_h(8, 9, 0), hours=72)["cpe_index_refresher"].missed_slots == []


def test_interval_early_run_after_restart_is_not_a_miss():
    _insert("cpe_index_refresher", _h(6, 10, 0))
    _insert("cpe_index_refresher", _h(6, 16, 0))
    _insert("cpe_index_refresher", _h(7, 16, 1))
    assert _st(now=_h(8, 9, 0), hours=72)["cpe_index_refresher"].missed_slots == []


def test_interval_gap_counts_one_slot_per_period():
    _insert("cpe_index_refresher", _h(4, 10, 0))
    _insert("cpe_index_refresher", _h(7, 11, 30))
    assert _st(now=_h(8, 9, 0), hours=96)["cpe_index_refresher"].missed_slots == [
        _h(5, 10, 0), _h(6, 10, 0), _h(7, 10, 0)]
    _wipe()
    _insert("cpe_index_refresher", _h(4, 10, 0))
    _insert("cpe_index_refresher", _h(7, 10, 30))
    assert _st(now=_h(8, 9, 0), hours=96)["cpe_index_refresher"].missed_slots == [_h(5, 10, 0), _h(6, 10, 0)]


def test_interval_tail_is_judged_from_the_last_run():
    _insert("cpe_index_refresher", _h(6, 10, 0))
    assert _st(now=_h(7, 10, 59), hours=48)["cpe_index_refresher"].missed_slots == []
    assert _st(now=_h(7, 11, 0), hours=48)["cpe_index_refresher"].missed_slots == [_h(7, 10, 0)]
    assert _st(now=_h(8, 12, 0), hours=72)["cpe_index_refresher"].missed_slots == [_h(7, 10, 0), _h(8, 10, 0)]


def test_interval_anchor_before_the_window():
    _insert("cpe_index_refresher", _h(1, 10, 0))
    assert _st(now=_h(8, 15, 5), hours=24)["cpe_index_refresher"].missed_slots == [_h(8, 10, 0)]
    assert _st(now=_h(8, 15, 5), hours=48)["cpe_index_refresher"].missed_slots == [_h(7, 10, 0), _h(8, 10, 0)]


def test_interval_twelve_hours():
    _insert("epss_refresher", _h(7, 2, 0))
    _insert("epss_refresher", _h(7, 14, 0))
    assert _st(now=_h(8, 15, 5), hours=24)["epss_refresher"].missed_slots == [_h(8, 2, 0), _h(8, 14, 0)]


def test_interval_sub_hour_has_no_missed_computation():
    assert job_runs._interval_missed(_h(8, 10, 0), [], _h(8, 0, 0), _h(8, 15, 0), job_runs.every(seconds=10)) == []
    assert job_runs._interval_missed(_h(8, 10, 0), [], _h(8, 0, 0), _h(8, 15, 0), job_runs.every(hours=1)) == [
        _h(8, 11, 0), _h(8, 12, 0), _h(8, 13, 0), _h(8, 14, 0)]


def test_status_cadence_on_each_job():
    st = _st()
    for j in job_runs.CADENCE:
        assert st[j].cadence is job_runs.CADENCE[j]


# 8 -- registration
@pytest.fixture
def sched(monkeypatch):
    s = BackgroundScheduler(timezone="UTC")  # never started
    monkeypatch.setattr(scheduler, "_scheduler", s)
    return s


def test_cron_minutes_come_from_cadence(sched):
    scheduler._register_capture_sweep()
    scheduler._register_rediscovery_tick()
    for jid in ("capture_sweep", "rediscovery_tick"):
        job = sched.get_job(jid)
        assert job is not None
        minute = {f.name: str(f) for f in job.trigger.fields}["minute"]
        assert minute == str(job_runs.CADENCE[jid].minute)


def test_job_run_purger_registered(sched):
    scheduler._register_job_run_purger()
    job = sched.get_job("job_run_purger")
    assert job is not None
    assert job.func is scheduler._run_job_run_purge
    assert job.trigger.interval == timedelta(hours=24)
    assert job.coalesce is True and job.max_instances == 1
    assert job.name == "Job run history daily retention"
    assert job.next_run_time > datetime.now(UTC) + timedelta(seconds=150)


REGISTRARS = {
    "alert_digests": scheduler._register_alert_digests,
    "rediscovery_tick": scheduler._register_rediscovery_tick,
    "capture_sweep": scheduler._register_capture_sweep,
    "run_reaper": scheduler._register_run_reaper,
    "nightly_rescore": scheduler._register_nightly_rescore,
    "epss_refresher": scheduler._register_epss_refresher,
    "cpe_index_refresher": scheduler._register_cpe_index_refresher,
    "cloud_ranges_refresher": scheduler._register_cloud_ranges_refresher,
    "partition_maintenance": scheduler._register_partition_maintenance,
    "hygiene_scoring": scheduler._register_hygiene_scoring,
    "job_run_purger": scheduler._register_job_run_purger,
    "llm_ledger_pruner": scheduler._register_llm_ledger_pruner,
    "chat_transcript_purger": scheduler._register_chat_transcript_purger,
    "report_purger": scheduler._register_report_purger,
    "llm_models_refresher": scheduler._register_llm_models_refresher,
    "page_capture": scheduler._register_page_capture,
    "ct_refresher": scheduler._register_ct_refresher,
    "capture_tokens": scheduler._register_capture_tokens,
    "tenancy_enricher": scheduler._register_tenancy_enricher,
    "tenancy_tls": scheduler._register_tenancy_tls,
}

WRAPPERS = {
    "page_capture": scheduler._run_page_capture,
    "ct_refresher": scheduler._run_ct_refresher,
    "capture_tokens": scheduler._run_capture_tokens,
    "tenancy_enricher": scheduler._run_tenancy_enricher,
    "tenancy_tls": scheduler._run_tenancy_tls,
}


@pytest.fixture
def capture_env(monkeypatch):
    """What `_register_capture_tokens` needs to schedule: S3 store with GCS workload identity."""
    monkeypatch.setenv("CAPTURE_STORE", "s3")
    monkeypatch.setenv("CAPTURE_S3_AUTH", "gcs-wi")
    monkeypatch.setenv("CAPTURE_S3_ENDPOINT", "https://storage.googleapis.com")
    monkeypatch.setenv("CAPTURE_S3_PATH_STYLE", "true")
    for k, v in (("CAPTURE_S3_BUCKET_JOBS", "jobs-bucket"), ("CAPTURE_S3_BUCKET_RESULTS", "results-bucket"),
                 ("CAPTURE_S3_BUCKET_PROXYLOG", "proxylog-bucket"), ("CAPTURE_S3_BUCKET_IMAGES", "images-bucket")):
        monkeypatch.setenv(k, v)


def test_every_cadence_job_registers_its_trigger(sched, capture_env):
    assert set(REGISTRARS) == set(job_runs.CADENCE)
    for jid, register in REGISTRARS.items():
        cadence = job_runs.CADENCE[jid]
        register()
        job = sched.get_job(jid)
        assert job is not None, jid
        assert job.coalesce is True and job.max_instances == 1, jid
        if jid in WRAPPERS:
            assert job.func is WRAPPERS[jid], jid  # never a bare tick
        if cadence.kind == "interval":
            assert isinstance(job.trigger, IntervalTrigger), jid
            assert job.trigger.interval == cadence.every, jid
        else:
            fields = {f.name: str(f) for f in job.trigger.fields}
            assert fields["minute"] == str(cadence.minute), jid
            expected_hour = str(cadence.hour) if cadence.kind == "daily_at" else "*"
            assert fields["hour"] == expected_hour, jid
            assert str(job.trigger.timezone) == "UTC", jid


def test_every_scheduled_id_has_a_cadence():
    ids = set(re.findall(r'\bid="([a-z_]+)"', inspect.getsource(scheduler)))
    assert ids == set(job_runs.CADENCE)


# 9 -- scheduler wrappers
def _one(job):
    rows = _rows(job)
    assert len(rows) == 1, rows
    return rows[0]


def _check(job, reason, items, counts):
    r = _one(job)
    assert r.finish_reason == reason and r.items_selected == items and r.counts == counts
    assert r.error is None
    return r


def test_alert_digests_wrapper_records(monkeypatch):
    from app.services import digest
    monkeypatch.setattr(digest, "run_due", lambda: 2)
    scheduler._run_alert_digests()
    _check("alert_digests", "done", 2, {"digests_created": 2})


def test_nightly_rescore_wrapper_records(monkeypatch):
    from app.services import nightly_rescore
    monkeypatch.setattr(nightly_rescore, "run", lambda db: {
        "rescored": 5, "history_rows": 4, "promotions": 1, "elapsed_ms": 99})
    scheduler._run_nightly_rescore()
    _check("nightly_rescore", "done", 5, {"rescored": 5, "history_rows": 4, "promotions": 1})


def test_epss_wrapper_records_and_prune_runs_after_a_failed_refresh(monkeypatch):
    from app.services import epss_history_service
    monkeypatch.setattr(epss_history_service, "refresh_all_active", lambda db: 7)
    monkeypatch.setattr(epss_history_service, "prune_expired", lambda db: 2)
    scheduler._run_epss_refresh()
    _check("epss_refresher", "done", 7, {"upserted": 7, "pruned": 2})
    _wipe()

    pruned = []

    def boom(db):
        raise RuntimeError("boom")

    monkeypatch.setattr(epss_history_service, "refresh_all_active", boom)
    monkeypatch.setattr(epss_history_service, "prune_expired", lambda db: pruned.append(1) or 2)
    scheduler._run_epss_refresh()
    r = _one("epss_refresher")
    assert r.finish_reason == "error" and r.error == "RuntimeError" and r.counts == {}
    assert pruned == [1]


def test_epss_double_failure_records_the_refresh_error_and_logs_the_prune_one(monkeypatch, caplog):
    from app.services import epss_history_service

    def refresh_boom(db):
        raise ValueError("refresh")

    def prune_boom(db):
        raise RuntimeError("prune")

    monkeypatch.setattr(epss_history_service, "refresh_all_active", refresh_boom)
    monkeypatch.setattr(epss_history_service, "prune_expired", prune_boom)
    with caplog.at_level(logging.ERROR):
        scheduler._run_epss_refresh()  # must not raise
    r = _one("epss_refresher")
    assert r.finish_reason == "error" and r.error == "ValueError"
    assert any("retention also failed" in rec.getMessage() for rec in caplog.records)
    assert any("EPSS history refresh failed" in rec.getMessage() for rec in caplog.records)
    # Control: a prune failure after a GOOD refresh is the run's error.
    _wipe()
    monkeypatch.setattr(epss_history_service, "refresh_all_active", lambda db: 3)
    scheduler._run_epss_refresh()
    assert _one("epss_refresher").error == "RuntimeError"


def test_cpe_index_wrapper_records(monkeypatch):
    from app.services import cpe_cve_sync
    monkeypatch.setattr(cpe_cve_sync, "refresh", lambda db: {
        "seeded": 10, "delta": 3, "days_done": 4, "days_left": 0, "stopped": "done"})
    scheduler._run_cpe_index_refresh()
    _check("cpe_index_refresher", "done", 13, {"seeded": 10, "delta": 3, "days_done": 4, "days_left": 0})


def test_cloud_ranges_wrapper_records_and_a_rejected_refresh_is_an_error(monkeypatch):
    from app.services import cloud_ranges
    ok = RefreshResult(ok=True, changed=True, record_count=12, dataset_sha256="x")
    monkeypatch.setattr(cloud_ranges, "refresh", lambda db: ok)
    scheduler._run_cloud_ranges_refresh()
    _check("cloud_ranges_refresher", "done", 12, {"changed": 1, "record_count": 12})
    _wipe()
    bad = RefreshResult(ok=False, changed=False, record_count=0, dataset_sha256=None, reason="bad_manifest")
    monkeypatch.setattr(cloud_ranges, "refresh", lambda db: bad)
    scheduler._run_cloud_ranges_refresh()
    r = _one("cloud_ranges_refresher")
    assert r.finish_reason == "error" and r.error == "RefreshFailed" and r.counts == {}


def test_partition_wrapper_records(monkeypatch):
    from app.services import partition_maintenance
    monkeypatch.setattr(partition_maintenance, "run", lambda db: {
        "t1": {"created": ["a", "b"], "dropped": ["c"], "retained": 4}})
    scheduler._run_partition_maintenance()
    _check("partition_maintenance", "done", 3, {"created": 2, "dropped": 1, "retained": 4})


def test_hygiene_wrapper_records(monkeypatch):
    from app.services import hygiene_scorer
    monkeypatch.setattr(hygiene_scorer, "run", lambda db: {
        "scored": 8, "excluded": 1, "deleted": 2, "history_rows": 3, "elapsed_ms": 5})
    scheduler._run_hygiene_scoring()
    _check("hygiene_scoring", "done", 8, {"scored": 8, "excluded": 1, "deleted": 2, "history_rows": 3})


def test_with_session_commits_only_when_asked():
    t = job_runs._now()

    def work(db):
        db.add(JobRun(job="probe", started_at=t, finished_at=t, finish_reason="done",
                      items_selected=0, counts={}))

    scheduler._with_session(work, commit=True)()
    assert len(_rows("probe")) == 1
    _wipe()
    scheduler._with_session(work)()
    assert _rows("probe") == []

    def failing(db):
        work(db)
        db.flush()
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        scheduler._with_session(failing, commit=True)()
    assert _rows("probe") == []


def test_llm_ledger_wrapper_records(monkeypatch):
    from app.services import llm_connector
    monkeypatch.setattr(llm_connector, "prune_ledger", lambda db: 4)
    scheduler._run_llm_ledger_prune()
    _check("llm_ledger_pruner", "done", 4, {"deleted": 4})


def test_chat_transcript_wrapper_records(monkeypatch):
    from app.services import chat
    monkeypatch.setattr(chat, "purge_transcripts", lambda db: 5)
    scheduler._run_chat_transcript_purge()
    _check("chat_transcript_purger", "done", 5, {"deleted": 5})


def test_report_purge_wrapper_records(monkeypatch):
    from app.services import reports
    monkeypatch.setattr(reports, "purge_reports", lambda db: 6)
    scheduler._run_report_purge()
    _check("report_purger", "done", 6, {"deleted": 6})


def test_llm_models_wrapper_not_configured_and_configured(monkeypatch):
    from app.services import llm_connector
    spy = []
    monkeypatch.setattr(llm_connector, "is_configured", lambda db: False)
    monkeypatch.setattr(llm_connector, "refresh_allowed_models", lambda db: spy.append(1))
    scheduler._run_llm_models_refresh()
    _check("llm_models_refresher", "not_configured", 0, {})
    assert spy == []
    _wipe()

    class _Allowed:
        entries = [1, 2, 3]

    monkeypatch.setattr(llm_connector, "is_configured", lambda db: True)
    monkeypatch.setattr(llm_connector, "refresh_allowed_models", lambda db: _Allowed())
    scheduler._run_llm_models_refresh()
    _check("llm_models_refresher", "done", 3, {"models": 3})


def test_run_reaper_wrapper_startup_then_stale_and_flag_set_before_call(monkeypatch):
    from app.services import run_reaper
    startup_calls = []
    monkeypatch.setattr(scheduler, "_reaper_started", False)
    monkeypatch.setattr(run_reaper, "reap_at_startup", lambda db: startup_calls.append(1) or 2)
    monkeypatch.setattr(run_reaper, "reap_ingest_runs_at_startup", lambda db: 1)
    monkeypatch.setattr(run_reaper, "reap_stale", lambda db: 3)
    monkeypatch.setattr(run_reaper, "reap_stale_ingest_runs", lambda db: 4)

    scheduler._run_run_reaper()
    _check("run_reaper", "done", 3, {"startup": 1, "runs": 2, "ingest_runs": 1})
    _wipe()
    scheduler._run_run_reaper()
    _check("run_reaper", "done", 7, {"startup": 0, "runs": 3, "ingest_runs": 4})
    _wipe()

    def boom(db):
        startup_calls.append(1)
        raise RuntimeError("boom")

    startup_calls.clear()
    monkeypatch.setattr(scheduler, "_reaper_started", False)
    monkeypatch.setattr(run_reaper, "reap_at_startup", boom)
    scheduler._run_run_reaper()
    r = _one("run_reaper")
    assert r.finish_reason == "error" and r.error == "RuntimeError" and r.counts == {}
    assert scheduler._reaper_started is True
    _wipe()
    scheduler._run_run_reaper()  # stale path: the failed startup sweep is not retried
    assert startup_calls == [1]
    _check("run_reaper", "done", 7, {"startup": 0, "runs": 3, "ingest_runs": 4})


_WRAPPER_FAILURES = [
    ("alert_digests", scheduler._run_alert_digests, "app.services.digest", ["run_due"]),
    ("run_reaper", scheduler._run_run_reaper, "app.services.run_reaper", ["reap_stale"]),
    ("nightly_rescore", scheduler._run_nightly_rescore, "app.services.nightly_rescore", ["run"]),
    ("epss_refresher", scheduler._run_epss_refresh, "app.services.epss_history_service",
     ["refresh_all_active", "prune_expired"]),
    ("cpe_index_refresher", scheduler._run_cpe_index_refresh, "app.services.cpe_cve_sync", ["refresh"]),
    ("cloud_ranges_refresher", scheduler._run_cloud_ranges_refresh, "app.services.cloud_ranges", ["refresh"]),
    ("partition_maintenance", scheduler._run_partition_maintenance, "app.services.partition_maintenance", ["run"]),
    ("hygiene_scoring", scheduler._run_hygiene_scoring, "app.services.hygiene_scorer", ["run"]),
    ("job_run_purger", scheduler._run_job_run_purge, "app.services.job_runs", ["purge"]),
    ("llm_ledger_pruner", scheduler._run_llm_ledger_prune, "app.services.llm_connector", ["prune_ledger"]),
    ("chat_transcript_purger", scheduler._run_chat_transcript_purge, "app.services.chat", ["purge_transcripts"]),
    ("report_purger", scheduler._run_report_purge, "app.services.reports", ["purge_reports"]),
    ("llm_models_refresher", scheduler._run_llm_models_refresh, "app.services.llm_connector", ["is_configured"]),
]


@pytest.mark.parametrize("job,run,module,attrs", _WRAPPER_FAILURES, ids=[c[0] for c in _WRAPPER_FAILURES])
def test_every_wrapper_swallows_and_records_a_failure(monkeypatch, caplog, job, run, module, attrs):
    import importlib
    mod = importlib.import_module(module)

    def boom(*a, **k):
        raise RuntimeError("boom")

    for attr in attrs:
        monkeypatch.setattr(mod, attr, boom)
    if job == "run_reaper":
        monkeypatch.setattr(scheduler, "_reaper_started", True)
    with caplog.at_level(logging.ERROR, logger=scheduler.log.name):
        run()  # must return normally
    r = _one(job)
    assert r.finish_reason == "error" and r.error == "RuntimeError" and r.counts == {}
    assert any(rec.levelno == logging.ERROR and "failed" in rec.getMessage() for rec in caplog.records)


# 10 -- seconds-scale ticks: record_idle + LAST_TICK
@pytest.fixture
def last_tick(monkeypatch):
    d: dict = {}
    monkeypatch.setattr(job_runs, "LAST_TICK", d)
    return d


def _outcome(items, counts):
    return lambda r: job_runs.RunOutcome("done", items, counts)


def test_idle_tick_writes_no_row_but_stamps_last_tick(last_tick):
    out = job_runs.run_recorded("page_capture", lambda: "r", _outcome(0, {"ingested": 0, "errors": 0}),
                                record_idle=False)
    assert out == "r"
    assert _rows("page_capture") == []
    stamp = last_tick["page_capture"]
    assert stamp.tzinfo is not None
    assert abs((datetime.now(UTC) - stamp).total_seconds()) < 60


def test_tick_that_did_work_is_recorded(last_tick):
    job_runs.run_recorded("page_capture", lambda: "r", _outcome(2, {"ingested": 2, "errors": 0}), record_idle=False)
    _check("page_capture", "done", 2, {"ingested": 2, "errors": 0})


def test_tick_with_errors_and_no_items_is_recorded(last_tick):
    job_runs.run_recorded("page_capture", lambda: "r", _outcome(0, {"errors": 1}), record_idle=False)
    _check("page_capture", "done", 0, {"errors": 1})


def test_tick_failure_is_recorded_reraised_and_stamped(last_tick):
    def boom():
        raise ValueError("secret detail")

    with pytest.raises(ValueError):
        job_runs.run_recorded("page_capture", boom, _outcome(0, {}), record_idle=False)
    r = _one("page_capture")
    assert r.finish_reason == "error" and r.error == "ValueError" and r.counts == {}
    assert "page_capture" in last_tick


def test_record_idle_default_keeps_slice_1_behaviour(last_tick):
    job_runs.run_recorded("alert_digests", lambda: "r", _outcome(0, {}))
    assert len(_rows("alert_digests")) == 1


@pytest.mark.parametrize("items,counts,idle", [
    (0, {}, True), (0, {"errors": 0}, True), (0, {"errors": 1}, False), (1, {}, False), (0, {"x": 5}, True),
])
def test_is_idle(items, counts, idle):
    assert job_runs.is_idle(job_runs.RunOutcome("done", items, counts)) is idle


def test_run_and_record_reports_whether_a_row_was_written(last_tick):
    assert job_runs.run_and_record("page_capture", lambda: "r", _outcome(0, {}), record_idle=False) == ("r", False)
    assert job_runs.run_and_record("page_capture", lambda: "r", _outcome(1, {}), record_idle=False) == ("r", True)
    assert job_runs.run_and_record("page_capture", lambda: "r", _outcome(0, {})) == ("r", True)
    assert len(_rows("page_capture")) == 2


def test_status_returns_last_tick_at(last_tick):
    t = datetime(2026, 11, 10, 12, 0, 5, tzinfo=UTC)
    last_tick["tenancy_tls"] = t
    st = _st()
    assert st["tenancy_tls"].last_tick_at == t
    assert all(x.last_tick_at is None for j, x in st.items() if j != "tenancy_tls")


def test_seconds_scale_mappers():
    assert job_runs.page_capture_tick_outcome(PageCaptureTick(True, 2, 1, 0, 3, 1)) == job_runs.RunOutcome(
        "done", 7, {"ingested": 2, "swept": 1, "claims_swept": 0, "pruned": 3, "limits_written": 1, "errors": 1})
    o = job_runs.ct_refresher_outcome(CtRefresherTick(3, 5, 2, 1))
    assert o.items_selected == 3 and o.counts == {"targets": 3, "budget": 5, "refreshed": 2, "errors": 1}
    o = job_runs.capture_tokens_outcome({"worker": "published", "proxy": "mint_failed"})
    assert o.items_selected == 2
    assert o.counts == {"fresh": 0, "published": 1, "mint_failed": 1, "refused_floor": 0, "conflict": 0, "errors": 1}
    o = job_runs.capture_tokens_outcome({"worker": "fresh", "proxy": "fresh"})
    assert o.items_selected == 0 and job_runs.is_idle(o)
    o = job_runs.capture_tokens_outcome({})
    assert o.items_selected == 0 and set(o.counts.values()) == {0}
    o = job_runs.tenancy_enricher_outcome(TenancyEnricherTick(200, 150, 2, stale_dataset=True))
    assert o.items_selected == 200
    assert o.counts == {"selected": 200, "enriched": 150, "stale_dataset": 1, "no_dataset": 0, "errors": 2}
    o = job_runs.tenancy_tls_outcome(TenancyTlsTick(25, 20, 5, 10, 4, 1))
    assert o.items_selected == 25 and o.counts["errors"] == 1 and o.counts["unreachable"] == 4


def test_page_capture_wrapper_records_only_work(monkeypatch):
    monkeypatch.setattr(page_capture, "tick", lambda: PageCaptureTick(False, 0, 0, 0, 0, 0))
    scheduler._run_page_capture()
    assert _rows("page_capture") == []
    monkeypatch.setattr(page_capture, "tick", lambda: PageCaptureTick(False, 2, 0, 0, 0, 0))
    scheduler._run_page_capture()
    r = _one("page_capture")
    assert r.finish_reason == "done" and r.items_selected == 2


def test_capture_tokens_wrapper_logs_no_token(monkeypatch, caplog):
    from app.services import capture_token_secret as ts

    def boom():
        raise RuntimeError("secret ABCDEF-TOKEN-336")

    monkeypatch.setattr(ts, "tick", boom)
    with caplog.at_level(logging.ERROR):
        scheduler._run_capture_tokens()  # must not raise
    r = _one("capture_tokens")
    assert r.error == "RuntimeError"
    assert "ABCDEF-TOKEN-336" not in caplog.text
    assert "RuntimeError" in caplog.text


def test_tenancy_tls_wrapper_records_a_worker_outage(monkeypatch):
    def down():
        raise tenancy_tls.WorkerUnavailable("x")

    monkeypatch.setattr(tenancy_tls, "tick", down)
    scheduler._run_tenancy_tls()  # must not raise
    assert _one("tenancy_tls").error == "WorkerUnavailable"


def test_capture_tokens_wrapper_records_published(monkeypatch):
    from app.services import capture_token_secret as ts
    monkeypatch.setattr(ts, "tick", lambda: {"worker": "published", "proxy": "fresh"})
    scheduler._run_capture_tokens()
    r = _one("capture_tokens")
    assert r.finish_reason == "done" and r.items_selected == 1
