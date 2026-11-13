"""GET/PUT /api/settings/logging (planning#335). Synthetic data only.

Run with:  backend/scripts/test.sh app/tests/test_log_settings_api.py
"""

import pytest

from app.core import logging as app_logging
from app.core.database import SessionLocal
from app.models.app_settings import AppSetting
from app.models.audit import AuditLog
from app.models.user import UserRole
from app.services import log_settings as ls
from app.tests._org_world import World, client

VIEWER = UserRole.VIEWER.value
URL = "/api/settings/logging"
KEYS = (ls.QUEUE_MAX_KEY, ls.BATCH_MAX_KEY, ls.FLUSH_INTERVAL_S_KEY)
DEFAULTS = {"queue_max_records": 10_000, "batch_max_records": 200, "flush_interval_s": 1.0}
# (field, key, below, valid, above)
FIELDS = [
    ("queue_max_records", ls.QUEUE_MAX_KEY, 999, 5_000, 100_001),
    ("batch_max_records", ls.BATCH_MAX_KEY, 9, 50, 1_001),
    ("flush_interval_s", ls.FLUSH_INTERVAL_S_KEY, 0.1, 2.5, 10.5),
]


def _wipe():
    with SessionLocal() as s:
        s.query(AppSetting).filter(AppSetting.key.in_(KEYS)).delete(synchronize_session=False)
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


def _body(h):
    r = client.get(URL, headers=h)
    assert r.status_code == 200
    return r.json()


def _stored(h):
    b = _body(h)
    return {k: b[k] for k in DEFAULTS}


def _audit_changes(user_id):
    with SessionLocal() as s:
        return [x.detail.get("changes", {}) for x in
                s.query(AuditLog).filter(AuditLog.user_id == user_id).all() if x.detail]


def _log_changes(user_id):
    return [c for c in _audit_changes(user_id) if any(k.startswith("logs_") for k in c)]


def test_get_returns_defaults_and_the_active_bound(w):
    h = w.headers(user=w.user())
    b = _body(h)
    assert {k: b[k] for k in DEFAULTS} == DEFAULTS
    assert b["queue_max_records_active"] == app_logging.db_handler.queue.maxsize
    assert set(b) == set(DEFAULTS) | {"queue_max_records_active"}


@pytest.mark.parametrize("field,key,below,valid,above", FIELDS)
def test_put_persists_each_field(w, field, key, below, valid, above):
    h = w.headers(user=w.user())
    r = client.put(URL, headers=h, json={field: valid})
    assert r.status_code == 200 and r.json()[field] == valid
    assert _body(h)[field] == valid
    assert valid != DEFAULTS[field]  # the change is a real one
    with SessionLocal() as s:
        assert s.query(AppSetting).filter(AppSetting.key == key).one().value == str(valid)


@pytest.mark.parametrize("field,key,below,valid,above", FIELDS)
def test_put_out_of_bounds_is_422_and_changes_nothing(w, field, key, below, valid, above):
    h = w.headers(user=w.user())
    assert client.put(URL, headers=h, json={field: valid}).status_code == 200
    before = _stored(h)
    for bad in (below, above):
        assert client.put(URL, headers=h, json={field: bad}).status_code == 422
    assert _stored(h) == before


@pytest.mark.parametrize("field", ["queue_max_records", "batch_max_records"])
def test_put_non_integer_for_int_fields_is_422(w, field):
    h = w.headers(user=w.user())
    before = _stored(h)
    for bad in (1500.5, "abc"):
        assert client.put(URL, headers=h, json={field: bad}).status_code == 422
    assert _stored(h) == before


def test_partial_put_leaves_the_others_alone(w):
    h = w.headers(user=w.user())
    assert client.put(URL, headers=h, json={"batch_max_records": 50}).status_code == 200
    assert client.put(URL, headers=h, json={"flush_interval_s": 2.5}).status_code == 200
    assert _stored(h) == {"queue_max_records": 10_000, "batch_max_records": 50, "flush_interval_s": 2.5}


def test_put_queue_bound_does_not_change_the_active_bound(w):
    h = w.headers(user=w.user())
    active = app_logging.db_handler.queue.maxsize
    new = 5_000 if active != 5_000 else 6_000
    b = client.put(URL, headers=h, json={"queue_max_records": new}).json()
    assert b["queue_max_records"] == new
    assert b["queue_max_records_active"] == app_logging.db_handler.queue.maxsize == active
    assert b["queue_max_records_active"] != new


def test_put_audit_carries_real_from_and_to(w):
    admin = w.user()
    h = w.headers(user=admin)
    assert client.put(URL, headers=h, json={"queue_max_records": 5_000, "flush_interval_s": 2.5}
                      ).status_code == 200
    assert _log_changes(admin.id) == [{
        "logs_queue_max_records": {"from": 10_000, "to": 5_000},
        "logs_flush_interval_s": {"from": 1.0, "to": 2.5},
    }]
    # same values again -> no new change detail
    assert client.put(URL, headers=h, json={"queue_max_records": 5_000, "flush_interval_s": 2.5}
                      ).status_code == 200
    assert len(_log_changes(admin.id)) == 1


def test_permissions(w):
    assert client.get(URL).status_code in (401, 403)
    assert client.put(URL, json={"batch_max_records": 50}).status_code in (401, 403)
    for role in UserRole:
        if role.value == UserRole.ADMIN.value:
            continue
        h = w.headers(role=role.value)
        assert client.get(URL, headers=h).status_code == 403, role
        assert client.put(URL, headers=h, json={"batch_max_records": 50}).status_code == 403, role
    admin = w.headers(user=w.user())
    assert _stored(admin) == DEFAULTS  # the 403 paths wrote nothing
