"""GET/PUT /api/settings/cpe-index (planning#369). Synthetic data only.

Run with:  backend/scripts/test.sh app/tests/test_cpe_index_settings_api.py
"""

import pytest

from app.core.database import SessionLocal
from app.models.app_settings import AppSetting
from app.models.audit import AuditLog
from app.services import cpe_cve_sync as cs
from app.tests._org_world import World, client

URL = "/api/settings/cpe-index"
KEYS = (cs.PAGE_SIZE_KEY, cs.RUN_TIME_LIMIT_KEY)
DEFAULTS = {"page_size": 500, "run_time_limit_seconds": 600}
# (field, key, below, valid, above)
FIELDS = [
    ("page_size", cs.PAGE_SIZE_KEY, 49, 1000, 2001),
    ("run_time_limit_seconds", cs.RUN_TIME_LIMIT_KEY, 59, 1200, 3601),
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


def _changes(user_id):
    with SessionLocal() as s:
        out = [x.detail.get("changes", {}) for x in
               s.query(AuditLog).filter(AuditLog.user_id == user_id).all() if x.detail]
    return [c for c in out if any(k.startswith("cpe_index_") for k in c)]


def test_get_returns_defaults(w):
    assert _body(w.headers(user=w.user())) == DEFAULTS


@pytest.mark.parametrize("field,key,below,valid,above", FIELDS)
def test_put_persists_each_field(w, field, key, below, valid, above):
    h = w.headers(user=w.user())
    r = client.put(URL, headers=h, json={field: valid})
    assert r.status_code == 200 and r.json()[field] == valid
    assert _body(h)[field] == valid
    assert valid != DEFAULTS[field]
    with SessionLocal() as s:
        assert s.query(AppSetting).filter(AppSetting.key == key).one().value == str(valid)


@pytest.mark.parametrize("field,key,below,valid,above", FIELDS)
def test_put_out_of_bounds_is_422_and_changes_nothing(w, field, key, below, valid, above):
    h = w.headers(user=w.user())
    assert client.put(URL, headers=h, json={field: valid}).status_code == 200
    before = _body(h)
    for bad in (below, above):
        assert client.put(URL, headers=h, json={field: bad}).status_code == 422
    assert _body(h) == before


@pytest.mark.parametrize("field,key,below,valid,above", FIELDS)
def test_out_of_bounds_stored_value_reads_as_the_default(w, field, key, below, valid, above):
    h = w.headers(user=w.user())
    for bad in (str(below), str(above), "not-a-number"):
        _wipe()
        with SessionLocal() as s:
            s.add(AppSetting(key=key, value=bad))
            s.commit()
        assert _body(h) == DEFAULTS, bad


def test_put_audit_carries_real_from_and_to(w):
    admin = w.user()
    h = w.headers(user=admin)
    assert client.put(URL, headers=h, json={"page_size": 1000, "run_time_limit_seconds": 1200}
                      ).status_code == 200
    assert _changes(admin.id) == [{
        "cpe_index_page_size": {"from": 500, "to": 1000},
        "cpe_index_run_time_limit_seconds": {"from": 600, "to": 1200},
    }]
    assert client.put(URL, headers=h, json={"page_size": 1000}).status_code == 200
    assert len(_changes(admin.id)) == 1


def test_permissions(w):
    assert client.get(URL).status_code in (401, 403)
    assert client.put(URL, json={"page_size": 1000}).status_code in (401, 403)
    from app.models.user import UserRole
    for role in UserRole:
        if role.value == UserRole.ADMIN.value:
            continue
        h = w.headers(role=role.value)
        assert client.get(URL, headers=h).status_code == 403, role
        assert client.put(URL, headers=h, json={"page_size": 1000}).status_code == 403, role
    assert _body(w.headers(user=w.user())) == DEFAULTS
