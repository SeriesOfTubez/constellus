"""GET/PUT /api/settings/discovery (planning#320): the re-discovery pacing settings.
Synthetic data only. Shape copied from the capture-settings API tests.

Run with:  backend/scripts/test.sh app/tests/test_discovery_settings_api.py
"""

import pytest

from app.core.database import SessionLocal
from app.models.app_settings import AppSetting
from app.models.audit import AuditLog
from app.models.user import UserRole
from app.services.org_discovery import pacing
from app.tests._org_world import World, client

S = "/api/settings/discovery"
VIEWER = UserRole.VIEWER.value
_KEYS = (pacing.TIME_LIMIT_KEY, pacing.UNIT_PAUSE_KEY, pacing.DUE_BATCH_KEY,
         pacing.REFRESH_INTERVAL_KEY, pacing.FAILED_RETRY_KEY)
DEFAULTS = {
    "rediscovery_time_limit_seconds": 600, "rediscovery_unit_pause_seconds": 2, "rediscovery_due_batch": 200,
    "rediscovery_refresh_interval_days": 7, "rediscovery_failed_retry_days": 1,
}


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
    assert client.put(S, json={"rediscovery_due_batch": 50}).status_code in (401, 403)
    v = client.put(S, headers=w.headers(role=VIEWER), json={"rediscovery_due_batch": 50})
    assert v.status_code == 403
    assert _rows() == {}  # the 403 path was reached and wrote nothing
    assert client.put(S, headers=w.headers(), json={"rediscovery_due_batch": 50}).status_code == 200  # admin passes


def test_put_round_trips_and_audits_only_changed_keys(w):
    h = w.headers()
    new = {"rediscovery_time_limit_seconds": 900, "rediscovery_unit_pause_seconds": 5,
           "rediscovery_due_batch": 50, "rediscovery_refresh_interval_days": 14,
           "rediscovery_failed_retry_days": 3}
    r = client.put(S, headers=h, json=new)
    assert r.status_code == 200, r.text
    assert r.json() == new == client.get(S, headers=h).json()
    with SessionLocal() as s:
        p = pacing.read(s)  # the tick reads what the API wrote
    assert (p.time_limit_s, p.unit_pause_s, p.due_batch) == (900, 5, 50)
    assert (p.refresh_interval.days, p.failed_retry_after.days) == (14, 3)
    hit = [c for c in _audits() if c.get("discovery_rediscovery_due_batch") == {"from": 200, "to": 50}]
    assert hit and hit[0]["discovery_rediscovery_refresh_interval_days"] == {"from": 7, "to": 14}
    assert len([k for k in hit[0] if k.startswith("discovery_")]) == 5

    r2 = client.put(S, headers=h, json={"rediscovery_due_batch": 60, "rediscovery_unit_pause_seconds": 5})
    assert r2.status_code == 200
    hit2 = [c for c in _audits() if c.get("discovery_rediscovery_due_batch") == {"from": 50, "to": 60}]
    assert hit2 and "discovery_rediscovery_unit_pause_seconds" not in hit2[0]  # unchanged: not audited


@pytest.mark.parametrize("bad", [
    {"rediscovery_time_limit_seconds": 59}, {"rediscovery_time_limit_seconds": 3001},
    {"rediscovery_unit_pause_seconds": 0}, {"rediscovery_unit_pause_seconds": 61},
    {"rediscovery_due_batch": 9}, {"rediscovery_due_batch": 1001},
    {"rediscovery_refresh_interval_days": 0}, {"rediscovery_refresh_interval_days": 91},
    {"rediscovery_failed_retry_days": 0}, {"rediscovery_failed_retry_days": 31},
    {"rediscovery_due_batch": "x"},
])
def test_out_of_bounds_is_422_and_writes_nothing(w, bad):
    before = client.get(S, headers=w.headers()).json()
    assert before == DEFAULTS  # the baseline was read
    assert client.put(S, headers=w.headers(), json=bad).status_code == 422
    assert _rows() == {} and client.get(S, headers=w.headers()).json() == before


def test_failed_retry_over_refresh_is_422_against_the_stored_value(w):
    h = w.headers()
    assert client.put(S, headers=h, json={"rediscovery_refresh_interval_days": 3}).status_code == 200
    stored = _rows()
    assert stored[pacing.REFRESH_INTERVAL_KEY] == "3"
    r = client.put(S, headers=h, json={"rediscovery_failed_retry_days": 4})  # conflicts with the STORED 3
    assert r.status_code == 422
    assert r.json()["detail"] == "Retrying a failed item must not take longer than the refresh interval."
    assert _rows() == stored
    # the other direction: lowering refresh below the stored failed retry
    assert client.put(S, headers=h, json={"rediscovery_failed_retry_days": 3}).status_code == 200
    stored = _rows()
    assert client.put(S, headers=h, json={"rediscovery_refresh_interval_days": 2}).status_code == 422
    assert _rows() == stored
    assert client.put(S, headers=h, json={"rediscovery_failed_retry_days": 3}).status_code == 200  # equal is allowed


def test_failed_retry_over_refresh_in_one_put_is_422_and_a_consistent_pair_passes(w):
    h = w.headers()
    r = client.put(S, headers=h, json={"rediscovery_refresh_interval_days": 2, "rediscovery_failed_retry_days": 5})
    assert r.status_code == 422 and _rows() == {}
    ok = client.put(S, headers=h, json={"rediscovery_refresh_interval_days": 20, "rediscovery_failed_retry_days": 5})
    assert ok.status_code == 200
    assert (ok.json()["rediscovery_refresh_interval_days"], ok.json()["rediscovery_failed_retry_days"]) == (20, 5)
