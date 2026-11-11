"""GET /api/jobs/runs, /api/jobs/status and /api/settings/jobs (planning#329).
Synthetic data only.

Run with:  backend/scripts/test.sh app/tests/test_jobs_api.py
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.core.database import SessionLocal
from app.models.app_settings import AppSetting
from app.models.audit import AuditLog
from app.models.job_run import JobRun
from app.models.user import UserRole
from app.services import job_runs
from app.tests._org_world import World, client

VIEWER = UserRole.VIEWER.value
RUNS, STATUS, SETTINGS = "/api/jobs/runs", "/api/jobs/status", "/api/settings/jobs"
ROW_KEYS = {"id", "job", "started_at", "finished_at", "duration_seconds", "finish_reason",
            "items_selected", "counts", "error"}


def _wipe():
    with SessionLocal() as s:
        s.query(JobRun).delete(synchronize_session=False)
        s.query(AppSetting).filter(AppSetting.key == job_runs.RUN_HISTORY_DAYS_KEY).delete(synchronize_session=False)
        s.commit()


@pytest.fixture
def w():
    _wipe()
    world = World()
    try:
        yield world
    finally:
        world.close()
        _wipe()


def _add(job, started, seconds=5, reason="done", items=3, counts=None, error=None):
    with SessionLocal() as s:
        s.add(JobRun(job=job, started_at=started, finished_at=started + timedelta(seconds=seconds),
                     finish_reason=reason, items_selected=items, counts=counts or {"ok": items}, error=error))
        s.commit()


def _hour_slot(hours_back, minute):
    now = datetime.now(timezone.utc)
    return (now - timedelta(hours=hours_back)).replace(minute=minute, second=0, microsecond=0)


def test_jobs_routes_permissions(w):
    for url in (RUNS, STATUS):
        assert client.get(url).status_code == 401
        assert client.get(url, headers=w.headers(role=VIEWER)).status_code == 403
        assert client.get(url, headers=w.headers(role=UserRole.INTEGRATION_ADMIN.value)).status_code == 403
        assert client.get(url, headers=w.headers()).status_code == 200


def test_runs_ordering_filters_shape(w):
    h = w.headers()
    base = _hour_slot(5, 20)
    _add("rediscovery_tick", base, seconds=90)
    _add("capture_sweep", base + timedelta(minutes=20), seconds=7, reason="time_limit")
    _add("rediscovery_tick", base + timedelta(hours=1), seconds=2, reason="error", items=0,
         counts={}, error="ValueError")
    rows = client.get(RUNS, headers=h).json()
    assert [r["started_at"] for r in rows] == sorted((r["started_at"] for r in rows), reverse=True)
    assert len(rows) == 3
    assert all(set(r) == ROW_KEYS for r in rows)
    assert all(r["started_at"].endswith("+00:00") for r in rows)
    err = rows[0]
    assert err["finish_reason"] == "error" and err["error"] == "ValueError" and err["duration_seconds"] == 2.0
    oldest = rows[-1]
    assert oldest["duration_seconds"] == 90.0 and oldest["error"] is None and oldest["counts"] == {"ok": 3}
    by_job = client.get(RUNS, headers=h, params={"job": "capture_sweep"}).json()
    assert [r["job"] for r in by_job] == ["capture_sweep"]
    by_reason = client.get(RUNS, headers=h, params={"finish_reason": "time_limit"}).json()
    assert [r["finish_reason"] for r in by_reason] == ["time_limit"]
    assert len(client.get(RUNS, headers=h, params={"limit": 2}).json()) == 2


def test_runs_validation(w):
    h = w.headers()
    r = client.get(RUNS, headers=h, params={"finish_reason": "bogus"})
    assert r.status_code == 422 and "finish reason" in r.json()["detail"]
    assert client.get(RUNS, headers=h, params={"limit": 0}).status_code == 422
    assert client.get(RUNS, headers=h, params={"limit": 501}).status_code == 422
    assert client.get(RUNS, headers=h, params={"limit": 500}).status_code == 200


def test_status_empty(w):
    body = client.get(STATUS, headers=w.headers()).json()
    assert body["window_hours"] == 24
    assert [j["job"] for j in body["jobs"]] == list(job_runs.CADENCE)
    for j in body["jobs"]:
        assert j["last_run"] is None and j["recorded_since"] is None and j["missed_slots"] == []
        assert j["cadence"] == job_runs.CADENCE[j["job"]].to_dict()
        assert "cadence_minute" not in j


def test_status_missed_slot_and_last_run(w):
    h = w.headers()
    m = job_runs.CADENCE["rediscovery_tick"].minute
    # runs at 6,5,3,2 hours back; the slot 4 hours back is deliberately missing
    slot = {back: _hour_slot(back, m) for back in (6, 5, 4, 3, 2)}  # once: an hour may tick mid-test
    for back in (6, 5, 3, 2):
        _add("rediscovery_tick", slot[back])
    body = client.get(STATUS, headers=h, params={"hours": 24}).json()
    tick = next(j for j in body["jobs"] if j["job"] == "rediscovery_tick")
    cap = next(j for j in body["jobs"] if j["job"] == "capture_sweep")
    assert tick["last_run"] is not None and set(tick["last_run"]) == ROW_KEYS
    assert tick["last_run"]["started_at"] == slot[2].isoformat()
    assert tick["recorded_since"] == slot[6].isoformat()
    assert slot[4].isoformat() in tick["missed_slots"]
    assert slot[5].isoformat() not in tick["missed_slots"]
    assert cap["last_run"] is None and cap["missed_slots"] == []
    assert client.get(STATUS, headers=h, params={"hours": 0}).status_code == 422
    assert client.get(STATUS, headers=h, params={"hours": 169}).status_code == 422
    assert client.get(STATUS, headers=h, params={"hours": 168}).status_code == 200


def test_status_daily_and_interval_through_the_api(w):
    # No `now` parameter on the API: insert relative to the real clock, assert counts only.
    base = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    _add("nightly_rescore", (base - timedelta(days=2)).replace(hour=3))
    _add("cpe_index_refresher", base - timedelta(hours=50))
    body = client.get(STATUS, headers=w.headers(), params={"hours": 48}).json()
    jobs = {j["job"]: j for j in body["jobs"]}
    daily, interval = jobs["nightly_rescore"], jobs["cpe_index_refresher"]
    assert len(daily["missed_slots"]) >= 1
    assert len(interval["missed_slots"]) == 2
    for m in daily["missed_slots"] + interval["missed_slots"]:
        datetime.fromisoformat(m)


def _audit_changes(user_id):
    with SessionLocal() as s:
        return [x.detail.get("changes", {}) for x in
                s.query(AuditLog).filter(AuditLog.user_id == user_id).all() if x.detail]


def test_settings_jobs(w):
    admin = w.user()
    h = w.headers(user=admin)
    assert client.get(SETTINGS, headers=h).json() == {"run_history_days": 90}
    r = client.put(SETTINGS, headers=h, json={"run_history_days": 30})
    assert r.status_code == 200 and r.json() == {"run_history_days": 30}
    assert client.get(SETTINGS, headers=h).json() == {"run_history_days": 30}
    with SessionLocal() as s:
        assert job_runs.run_history_days(s) == 30  # purge reads what the API wrote
    changes = [c for c in _audit_changes(admin.id) if "jobs_run_history_days" in c]
    assert changes == [{"jobs_run_history_days": {"from": 90, "to": 30}}]
    # same value -> no new audit row
    assert client.put(SETTINGS, headers=h, json={"run_history_days": 30}).status_code == 200
    assert len([c for c in _audit_changes(admin.id) if "jobs_run_history_days" in c]) == 1
    for bad in (6, 366):
        assert client.put(SETTINGS, headers=h, json={"run_history_days": bad}).status_code == 422
    assert client.get(SETTINGS, headers=h).json() == {"run_history_days": 30}


def test_settings_jobs_permissions(w):
    assert client.get(SETTINGS).status_code in (401, 403)
    assert client.put(SETTINGS, json={"run_history_days": 30}).status_code in (401, 403)
    v = client.put(SETTINGS, headers=w.headers(role=VIEWER), json={"run_history_days": 30})
    assert v.status_code == 403
    with SessionLocal() as s:
        assert job_runs.run_history_days(s) == 90  # the 403 path wrote nothing
