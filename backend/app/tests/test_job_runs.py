"""Job run history (planning#329): outcome mappers, recording wrappers, purge,
missed-slot status, scheduler registration. Real constellus_test DB; synthetic data.

Run with:  scripts/test.sh app/tests/test_job_runs.py
"""
import logging
from datetime import datetime, timedelta, timezone

import pytest
from apscheduler.schedulers.background import BackgroundScheduler

from app.core.database import SessionLocal
from app.models.app_settings import AppSetting
from app.models.job_run import JobRun
from app.services import app_settings, job_runs, page_capture, scheduler
from app.services.org_discovery import rolling
from app.services.org_discovery.rolling import RollingResult
from app.services.page_capture import SweepResult

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


def test_purge_wrapper_commits(hset):
    _insert("capture_sweep", job_runs._now() - timedelta(days=91))
    scheduler._run_job_run_purge()
    assert _rows() == []


# 7 -- status
def _st(now=NOW, hours=24):
    with SessionLocal() as s:
        return {x.job: x for x in job_runs.status(s, now=now, hours=hours)}


def _h(day, hour, minute):
    return datetime(2026, 11, day, hour, minute, tzinfo=UTC)


def test_status_no_rows():
    st = _st()
    assert list(st) == ["rediscovery_tick", "capture_sweep"]
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


def test_status_jobs_are_independent():
    _insert("rediscovery_tick", _h(8, 13, 20))
    st = _st(hours=3)
    assert st["capture_sweep"].last_run is None and st["capture_sweep"].missed_slots == []
    assert st["rediscovery_tick"].last_run.job == "rediscovery_tick"


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
        assert minute == str(job_runs.CADENCE_MINUTE[jid])


def test_job_run_purger_registered(sched):
    scheduler._register_job_run_purger()
    job = sched.get_job("job_run_purger")
    assert job is not None
    assert job.func is scheduler._run_job_run_purge
    assert job.trigger.interval == timedelta(hours=24)
    assert job.coalesce is True and job.max_instances == 1
    assert job.name == "Job run history daily retention"
    assert job.next_run_time > datetime.now(UTC) + timedelta(seconds=150)
