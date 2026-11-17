"""GET/PUT /api/settings/cve-refresh (planning#360): the CVE refresh pacing settings.
Synthetic data only. Shape copied from test_discovery_settings_api.py.

Run with:  backend/scripts/test.sh app/tests/test_cve_refresh_settings_api.py
"""

import pytest

from app.core.database import SessionLocal
from app.models.app_settings import AppSetting
from app.models.audit import AuditLog
from app.models.user import UserRole
from app.services import cve_refresh_pacing as pacing
from app.tests._org_world import World, client

S = "/api/settings/cve-refresh"
VIEWER = UserRole.VIEWER.value
_KEYS = (pacing.TIME_LIMIT_KEY, pacing.DUE_BATCH_KEY, pacing.REFRESH_INTERVAL_KEY, pacing.FAILED_RETRY_KEY)
DEFAULTS = {"time_limit_seconds": 300, "due_batch": 500, "refresh_interval_hours": 24, "failed_retry_hours": 6}


def _wipe():
    with SessionLocal() as s:
        s.query(AppSetting).filter(AppSetting.key.in_(_KEYS)).delete(synchronize_session=False)
        s.commit()


def _rows() -> dict:
    with SessionLocal() as s:
        return {r.key: r.value for r in s.query(AppSetting).filter(AppSetting.key.in_(_KEYS))}


@pytest.fixture
def w():
    _wipe()
    world = World()
    try:
        yield world
    finally:
        world.close()
        _wipe()


def _audits() -> list[dict]:
    with SessionLocal() as s:
        return [x.detail.get("changes", {}) for x in
                s.query(AuditLog).order_by(AuditLog.occurred_at.desc()).limit(30).all() if x.detail]


def test_get_defaults(w):
    r = client.get(S, headers=w.headers())
    assert r.status_code == 200 and r.json() == DEFAULTS
    assert _rows() == {}  # reading writes nothing


def test_permissions(w):
    assert client.get(S).status_code in (401, 403)
    assert client.put(S, json={"due_batch": 50}).status_code in (401, 403)
    v = client.put(S, headers=w.headers(role=VIEWER), json={"due_batch": 50})
    assert v.status_code == 403
    assert _rows() == {}  # the 403 path was reached and wrote nothing
    assert client.put(S, headers=w.headers(), json={"due_batch": 50}).status_code == 200  # admin passes


def test_put_round_trips_and_audits_only_changed_keys(w):
    h = w.headers()
    new = {"time_limit_seconds": 900, "due_batch": 50, "refresh_interval_hours": 48, "failed_retry_hours": 3}
    r = client.put(S, headers=h, json=new)
    assert r.status_code == 200, r.text
    assert r.json() == new == client.get(S, headers=h).json()
    with SessionLocal() as s:
        p = pacing.read(s)  # the job reads what the API wrote
    assert (p.time_limit_s, p.due_batch) == (900, 50)
    assert (p.refresh_interval.total_seconds(), p.failed_retry_after.total_seconds()) == (48 * 3600, 3 * 3600)
    hit = [c for c in _audits() if c.get("cve_refresh_due_batch") == {"from": 500, "to": 50}]
    assert hit and hit[0]["cve_refresh_refresh_interval_hours"] == {"from": 24, "to": 48}
    assert len([k for k in hit[0] if k.startswith("cve_refresh_")]) == 4

    r2 = client.put(S, headers=h, json={"due_batch": 60, "time_limit_seconds": 900})
    assert r2.status_code == 200
    hit2 = [c for c in _audits() if c.get("cve_refresh_due_batch") == {"from": 50, "to": 60}]
    assert hit2 and "cve_refresh_time_limit_seconds" not in hit2[0]  # unchanged: not audited


@pytest.mark.parametrize("bad", [
    {"time_limit_seconds": 59}, {"time_limit_seconds": 3001},
    {"due_batch": 9}, {"due_batch": 5001},
    {"refresh_interval_hours": 0}, {"refresh_interval_hours": 721},
    {"failed_retry_hours": 0}, {"failed_retry_hours": 721},
    {"due_batch": "x"},
])
def test_out_of_bounds_is_422_and_writes_nothing(w, bad):
    before = client.get(S, headers=w.headers()).json()
    assert before == DEFAULTS  # the baseline was read
    assert client.put(S, headers=w.headers(), json=bad).status_code == 422
    assert _rows() == {} and client.get(S, headers=w.headers()).json() == before


def test_failed_retry_over_refresh_is_422(w):
    h = w.headers()
    r = client.put(S, headers=h, json={"refresh_interval_hours": 2, "failed_retry_hours": 5})
    assert r.status_code == 422 and _rows() == {}
    assert r.json()["detail"] == "Retrying a failed item must not take longer than the refresh interval."
    assert client.put(S, headers=h, json={"refresh_interval_hours": 20, "failed_retry_hours": 5}).status_code == 200
