"""planning#284 slice E: fixes from the security review. Config that cannot be
decrypted is never overwritten; asset delete's zone exclusion respects the
caller's rights; binding routes hide organizations the caller cannot see.

Real DB (throwaway `constellus_test`), synthetic names only. Every refusal
also proves its path was REACHED.

Run: backend/scripts/test.sh app/tests/test_connector_review_284.py
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.api import assets as assets_api
from app.connectors.cloudflare import CloudflareConnector
from app.core.database import SessionLocal
from app.main import app
from app.models.connector_instance import ConnectorInstance
from app.services import connector_instances as svc
from app.tests._org_world import hexid
from app.tests.test_connector_instance_api import BASE, ApiEnv, spy_cloudflare

client = TestClient(app)

UNREADABLE = "stored connector config cannot be decrypted; run the key-rotation script first"
GARBAGE = "not-a-fernet-token"


@pytest.fixture
def env():
    e = ApiEnv()
    e.purge()
    yield e
    e.close()


def _blob(env, instance_id) -> str | None:
    env.db.expire_all()
    return env.db.get(ConnectorInstance, instance_id).config_encrypted


def _garble(env, instance_id) -> None:
    env.db.execute(
        text("UPDATE connector_instances SET config_encrypted = :b WHERE id = :i"), {"b": GARBAGE, "i": instance_id}
    )
    env.db.commit()


# ── 3. never overwrite an undecryptable config ──────────────────────────────


def test_config_is_unreadable_unit(env):
    inst = env.raw("cloudflare", bound=env.ours())
    assert svc.config_is_unreadable(inst) is False  # nothing stored
    svc.update_config(env.db, inst, {"api_token": "t"})
    assert svc.config_is_unreadable(inst) is False
    inst.config_encrypted = GARBAGE
    assert svc.config_is_unreadable(inst) is True


def test_unreadable_config_refuses_every_merge_write(env, monkeypatch):
    spy_cloudflare(monkeypatch, ["zone-a.example.com"])
    inst = env.instance(env.admin, org=env.ours())
    iid = inst["id"]
    # reached: while readable, config and zones save, and the suggestion merges
    assert client.put(f"{BASE}/instances/{iid}/config", headers=env.admin, json={"config": {"api_token": "t2"}}).status_code == 200
    assert client.put(f"{BASE}/instances/{iid}/zones", headers=env.admin, json={"excluded_zones": ["x.example.com"]}).status_code == 200
    ok = client.post(f"{BASE}/cloudflare/binding-suggestion", headers=env.admin, json={"instance_id": iid, "config": {}})
    assert ok.status_code == 200, ok.text

    _garble(env, iid)
    before = _blob(env, iid)
    assert before == GARBAGE
    for r in (
        client.put(f"{BASE}/instances/{iid}/config", headers=env.admin, json={"config": {"api_token": "t3"}}),
        client.put(f"{BASE}/instances/{iid}/zones", headers=env.admin, json={"excluded_zones": ["y.example.com"]}),
        client.post(f"{BASE}/cloudflare/binding-suggestion", headers=env.admin, json={"instance_id": iid, "config": {}}),
    ):
        assert r.status_code == 409 and r.json() == {"detail": UNREADABLE}, r.text
    assert _blob(env, iid) == before  # byte-identical


# ── 4. asset delete: zone exclusion respects scope and permission ───────────


def _delete_apex(env, headers, apex):
    return client.request(
        "DELETE", "/api/assets/by-apex", headers=headers,
        json={"apex": apex, "asset_ids": [], "exclude_from_connector": True},
    )


def _excluded(env, iid) -> list[str]:
    env.db.expire_all()
    return svc.decrypted_config(env.db.get(ConnectorInstance, iid)).get("excluded_zones", [])


def test_asset_delete_exclusion_needs_configure_permission(env, monkeypatch):
    inst = env.instance(env.admin, org=env.ours())
    apex = f"excl-{hexid()}.example.com"
    env.target(apex, verified=True, connector_instance_id=inst["id"])
    # No built-in role holds ASSETS_DELETE without CONNECTORS_CONFIGURE, so the
    # permission check is made to fail for exactly that permission.
    from app.core.permissions import Permission

    monkeypatch.setattr(assets_api, "has_permission", lambda user, perm: perm != Permission.CONNECTORS_CONFIGURE)
    r = _delete_apex(env, env.iadmin, apex)
    assert r.status_code == 200 and r.json()["connector_excluded"] is None
    assert _excluded(env, inst["id"]) == []
    monkeypatch.undo()
    # reached: the identical request, permission held, excludes the zone
    r = _delete_apex(env, env.iadmin, apex)
    assert r.status_code == 200 and r.json()["connector_excluded"] == "cloudflare"
    assert _excluded(env, inst["id"]) == [apex]


def test_asset_delete_exclusion_needs_read_of_the_instance(env):
    deal, eng = env.deal("day_0")
    env.engagement(deal, "abandoned")  # the deal is closed to non-admins; its day_0 engagement still binds
    inst = env.instance(env.admin, org=deal)
    apex = f"hidden-{hexid()}.example.com"
    env.target(apex, verified=True, connector_instance_id=inst["id"], engagement_id=eng.id)
    r = _delete_apex(env, env.iadmin, apex)
    assert r.status_code == 200 and r.json()["connector_excluded"] is None  # and no type revealed
    assert _excluded(env, inst["id"]) == []
    r = _delete_apex(env, env.admin, apex)  # reached
    assert r.status_code == 200 and r.json()["connector_excluded"] == "cloudflare"
    assert _excluded(env, inst["id"]) == [apex]


def test_asset_delete_exclusion_skipped_for_an_unreadable_config(env):
    inst = env.instance(env.admin, org=env.ours())
    apex = f"unread-{hexid()}.example.com"
    env.target(apex, verified=True, connector_instance_id=inst["id"])
    env.db.commit()
    _garble(env, inst["id"])
    r = _delete_apex(env, env.admin, apex)
    assert r.status_code == 200 and r.json()["connector_excluded"] is None  # the delete proceeded
    assert _blob(env, inst["id"]) == GARBAGE


# ── 5. binding routes hide organizations the caller cannot see ──────────────


def test_binding_routes_hide_a_closed_deal_organization(env, monkeypatch):
    ours = env.ours()
    deal, eng = env.deal("day_0")
    env.engagement(deal, "abandoned")  # restricting and closed to non-admins; the day_0 one keeps it bindable
    zone = f"hid-{hexid()}.example.com"
    env.claim(deal, zone)
    # the estate organization matches nothing, so the hidden deal would be the top (only) match
    spy_cloudflare(monkeypatch, [zone])

    def bindable(headers):
        r = client.get(f"{BASE}/bindable-organizations", headers=headers)
        assert r.status_code == 200, r.text
        return {o["id"] for o in r.json()}

    def suggest(headers):
        r = client.post(f"{BASE}/cloudflare/binding-suggestion", headers=headers, json={"config": {"api_token": "t"}})
        assert r.status_code == 200, r.text
        return r.json()

    assert str(deal.id) in bindable(env.admin)  # reached: visible to admin
    s = suggest(env.admin)
    assert s["suggested_entity_id"] == str(deal.id) and [c["entity_id"] for c in s["candidates"]] == [str(deal.id)]

    hidden = bindable(env.iadmin)
    assert str(deal.id) not in hidden and str(ours.id) in hidden
    s = suggest(env.iadmin)
    assert s["candidates"] == [] and s["suggested_entity_id"] is None

    body = {"name": f"conn284-{hexid()}", "bound_entity_id": str(deal.id), "config": {}}
    r = client.post(f"{BASE}/cloudflare/instances", headers=env.iadmin, json=body)
    assert r.status_code == 422 and r.json()["detail"] == {"code": "binding_not_allowed", "reason": "not_visible"}
    # rebind of a visible instance to the hidden org is refused the same way
    mine = env.instance(env.iadmin, org=ours)
    r = client.patch(f"{BASE}/instances/{mine['id']}", headers=env.iadmin, json={"bound_entity_id": str(deal.id)})
    assert r.status_code == 422 and r.json()["detail"]["reason"] == "not_visible"
    # reached: admin may create the same binding
    r = client.post(f"{BASE}/cloudflare/instances", headers=env.admin, json=body)
    assert r.status_code == 201, r.text
