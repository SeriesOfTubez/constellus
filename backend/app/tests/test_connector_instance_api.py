"""Connector instance API (planning#284 slice B): create / read scope /
binding suggestion / delete / sync, through the real app with real tokens.

Real DB (the throwaway `constellus_test`), synthetic names only, the provider
transport spied (never a network call). Every refusal also proves the path
was REACHED: the same request with the precondition fixed succeeds.

Personas: `admin` (reads every engagement), `iadmin` (integration_admin: every
connector permission, but NOT `engagements.read_restricted`, so a pre_close
deal is closed to it), `scoped` (iadmin plus a viewer assignment on one
engagement), `viewer` (global viewer: reads connectors, configures nothing).

Run: backend/scripts/test.sh app/tests/test_connector_instance_api.py
"""

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.connectors.base import DiscoveredAsset, PhaseResult
from app.connectors.cloudflare import CloudflareConnector
from app.main import app
from app.models.connector_instance import ConnectorInstance
from app.models.role_assignment import RoleAssignment
from app.models.scan import ScanRun
from app.models.scope_candidate import ScopeCandidate
from app.models.target import Target, TargetType, VerificationMethod
from app.services import connector_instances as svc
from app.tests._org_world import hexid
from app.tests.test_connector_instances import Env

client = TestClient(app)
BASE = "/api/connectors"
TOKEN = "tok-stored-" + uuid.uuid4().hex[:8]


class ApiEnv(Env):
    def __init__(self) -> None:
        super().__init__()
        self.started = datetime.now(timezone.utc)
        self.admin = self.w.headers(role="admin")
        self.iadmin = self.w.headers(role="integration_admin")
        self.viewer = self.w.headers(role="viewer")
        self.scoped = None

    def scoped_to(self, eng) -> dict:
        user = self.w.user("integration_admin")
        self.db.add(RoleAssignment(user_id=user.id, role="viewer", engagement_id=eng.id))
        self.db.commit()
        return self.w.headers(user)

    def purge(self) -> None:
        super().purge()
        self.db.query(ScanRun).filter(
            ScanRun.name.like("Connector Sync:%"), ScanRun.started_at >= self.started
        ).delete(synchronize_session=False)
        self.db.commit()

    def instance(self, headers, type="cloudflare", org=None, name=None, config=None) -> dict:
        r = client.post(
            f"{BASE}/{type}/instances", headers=headers,
            json={"name": name or f"conn284-{hexid()}", "bound_entity_id": str(org.id) if org else None,
                  "config": {"api_token": TOKEN} if config is None else config},
        )
        assert r.status_code == 201, r.text
        return r.json()

    def claim(self, org, value) -> ScopeCandidate:
        c = self.w.candidate(org, value=value)
        self.db.execute(ScopeCandidate.__table__.update().where(ScopeCandidate.id == c.id).values(
            status="claimed", affiliated_entity_id=org.id, decided_at=datetime.now(timezone.utc),
            accepted_into="estate",
        ))
        self.db.commit()
        return c

    def target(self, value, **kw) -> Target:
        self.w.track_target(value)
        t = Target(id=uuid.uuid4(), type=TargetType.DOMAIN, value=value, **kw)
        self.db.add(t)
        self.db.commit()
        return t


@pytest.fixture
def env():
    e = ApiEnv()
    e.purge()
    yield e
    e.close()


class _Resp:
    def __init__(self, payload):
        self.payload = payload

    def json(self):
        return self.payload


def spy_cloudflare(monkeypatch, zones):
    """Replace the Cloudflare transport; returns the recorded requests."""
    calls = []

    def fake(url, *, headers=None, params=None, **kw):
        calls.append({"url": url, "headers": headers or {}})
        return _Resp({"result": [{"name": z} for z in zones], "result_info": {"total_pages": 1}})

    monkeypatch.setattr("app.connectors.cloudflare.connector_get", fake)
    return calls


def ids_in_catalogue(env, headers) -> set[str]:
    r = client.get(f"{BASE}/", headers=headers)
    assert r.status_code == 200, r.text
    return {i["id"] for t in r.json() for i in t["instances"]}


# ── create ──────────────────────────────────────────────────────────────────


def test_create_rules(env):
    ours = env.ours()
    deal, eng = env.deal("pre_close")
    body = lambda **kw: {"name": f"conn284-{hexid()}", "bound_entity_id": None, "config": {}, **kw}  # noqa: E731

    # a global type takes one instance
    assert client.post(f"{BASE}/shodan/instances", headers=env.iadmin, json=body()).status_code == 201
    r = client.post(f"{BASE}/shodan/instances", headers=env.iadmin, json=body())
    assert r.status_code == 409, r.text

    # an account type needs an organization
    r = client.post(f"{BASE}/cloudflare/instances", headers=env.iadmin, json=body())
    assert r.status_code == 422 and r.json()["detail"]["code"] == "binding_required"
    # ... a deal that has not closed is refused
    r = client.post(f"{BASE}/cloudflare/instances", headers=env.iadmin, json=body(bound_entity_id=str(deal.id)))
    assert r.status_code == 422 and r.json()["detail"]["code"] == "binding_not_allowed"
    # reached: the same request succeeds once the deal closes
    env.set_posture(eng, "day_0")
    r = client.post(f"{BASE}/cloudflare/instances", headers=env.iadmin, json=body(bound_entity_id=str(deal.id)))
    assert r.status_code == 201 and r.json()["bound_entity_id"] == str(deal.id) and r.json()["binding_ok"] is True
    assert "config" not in r.json() and TOKEN not in r.text

    # ours is fine; a duplicate name is not
    first = client.post(f"{BASE}/cloudflare/instances", headers=env.iadmin, json=body(bound_entity_id=str(ours.id), name="dup"))
    assert first.status_code == 201
    r = client.post(f"{BASE}/cloudflare/instances", headers=env.iadmin, json=body(bound_entity_id=str(ours.id), name="dup"))
    assert r.status_code == 409
    # a global type refuses a binding; an unknown type is 404
    r = client.post(f"{BASE}/naabu/instances", headers=env.iadmin, json=body(bound_entity_id=str(ours.id)))
    assert r.status_code == 422 and r.json()["detail"]["code"] == "binding_forbidden"
    assert client.post(f"{BASE}/nope/instances", headers=env.iadmin, json=body()).status_code == 404

    # the permission gate
    r = client.post(f"{BASE}/naabu/instances", headers=env.viewer, json=body())
    assert r.status_code == 403
    assert client.post(f"{BASE}/naabu/instances", headers=env.iadmin, json=body()).status_code == 201


def test_patch_rename_and_rebind(env):
    ours, deal_org = env.ours(), None
    deal_org, eng = env.deal("pre_close")
    inst = env.instance(env.iadmin, org=ours)
    url = f"{BASE}/instances/{inst['id']}"
    r = client.patch(url, headers=env.iadmin, json={"name": "renamed"})
    assert r.status_code == 200 and r.json()["name"] == "renamed" and r.json()["bound_entity_id"] == str(ours.id)
    r = client.patch(url, headers=env.iadmin, json={"bound_entity_id": str(deal_org.id)})
    assert r.status_code == 422
    r = client.patch(url, headers=env.iadmin, json={"bound_entity_id": None})
    assert r.status_code == 422 and r.json()["detail"]["code"] == "binding_required"
    env.set_posture(eng, "integrated")
    r = client.patch(url, headers=env.iadmin, json={"bound_entity_id": str(deal_org.id)})
    assert r.status_code == 200 and r.json()["bound_entity_name"] == deal_org.legal_name


# ── read scope ──────────────────────────────────────────────────────────────


def test_regressed_deal_instance_is_invisible_without_read_restricted(env):
    ours = env.ours()
    deal, eng = env.deal("day_0")
    inst = env.instance(env.admin, org=deal)
    own = env.instance(env.admin, org=ours)
    scoped = env.scoped_to(eng)
    sid = inst["id"]

    def probes(headers):
        u = f"{BASE}/instances/{sid}"
        return {
            "get": client.get(u, headers=headers).status_code,
            "config": client.get(f"{u}/config", headers=headers).status_code,
            "zones": client.get(f"{u}/zones", headers=headers).status_code,
            "put_config": client.put(f"{u}/config", headers=headers, json={"config": {}}).status_code,
            "patch": client.patch(u, headers=headers, json={"name": "x"}).status_code,
            "enable": client.post(f"{u}/enable", headers=headers).status_code,
            "disable": client.post(f"{u}/disable", headers=headers).status_code,
            "sync": client.post(f"{u}/sync", headers=headers).status_code,
            "test": client.post(f"{u}/test", headers=headers).status_code,
            "delete": client.delete(u, headers=headers).status_code,
        }

    # BEFORE the regression the integration admin sees it (path reached).
    assert sid in ids_in_catalogue(env, env.iadmin)
    assert client.get(f"{BASE}/instances/{sid}", headers=env.iadmin).status_code == 200
    assert client.get(f"{BASE}/instances/{sid}/config", headers=env.iadmin).status_code == 200

    env.set_posture(eng, "pre_close")

    # AFTER: absent from the list, 404 everywhere.
    assert sid not in ids_in_catalogue(env, env.iadmin) and own["id"] in ids_in_catalogue(env, env.iadmin)
    assert set(probes(env.iadmin).values()) == {404}, probes(env.iadmin)
    assert client.get(f"{BASE}/instances/{own['id']}", headers=env.iadmin).status_code == 200  # ours-bound unaffected
    # the global viewer cannot see it either (list and detail)
    assert sid not in ids_in_catalogue(env, env.viewer)
    assert client.get(f"{BASE}/instances/{sid}", headers=env.viewer).status_code == 404
    # admin still sees it; an engagement assignment opens it for reading
    assert sid in ids_in_catalogue(env, env.admin)
    assert client.get(f"{BASE}/instances/{sid}", headers=env.admin).status_code == 200
    assert sid in ids_in_catalogue(env, scoped)
    assert client.get(f"{BASE}/instances/{sid}", headers=scoped).status_code == 200
    # the 404 is the clause, not a missing row: nothing was written by the probes
    env.db.expire_all()
    assert env.db.get(ConnectorInstance, uuid.UUID(sid)).name == inst["name"]


def test_domains_route_is_scoped(env, monkeypatch):
    deal, eng = env.deal("day_0")
    inst = env.instance(env.admin, org=deal)
    spy_cloudflare(monkeypatch, [f"zone-{hexid()}.example.com"])
    manual = env.target(f"manual-{hexid()}.example.com", verified=True, verification_method=VerificationMethod.MANUAL,
                        engagement_id=eng.id)

    def domains(headers):
        r = client.get(f"{BASE}/domains", headers=headers)
        assert r.status_code == 200, r.text
        return r.json()

    rows = domains(env.iadmin)
    assert any(d["connector_instance_id"] == inst["id"] for d in rows)
    assert any(d["domain"] == manual.value for d in rows)
    env.set_posture(eng, "pre_close")
    rows = domains(env.iadmin)
    assert not any(d["connector_instance_id"] == inst["id"] for d in rows)
    assert not any(d["domain"] == manual.value for d in rows)
    rows = domains(env.admin)
    assert any(d["connector_instance_id"] == inst["id"] and d["connector_instance_name"] == inst["name"] for d in rows)
    assert any(d["domain"] == manual.value for d in rows)


# ── sync refusals ───────────────────────────────────────────────────────────


def test_sync_refused_when_binding_regressed_or_disabled(env, monkeypatch):
    monkeypatch.setattr(CloudflareConnector, "list_domains", lambda self, config: [])
    deal, eng = env.deal("day_0")
    inst = env.instance(env.admin, org=deal)
    url = f"{BASE}/instances/{inst['id']}/sync"
    assert client.post(url, headers=env.admin).status_code == 202  # reached

    env.set_posture(eng, "pre_close")
    r = client.post(url, headers=env.admin)
    assert r.status_code == 409 and r.json()["detail"]["reason"] == "deal_not_closed"
    env.set_posture(eng, "day_0")
    assert client.post(url, headers=env.admin).status_code == 202

    assert client.post(f"{BASE}/instances/{inst['id']}/disable", headers=env.admin).status_code == 200
    r = client.post(url, headers=env.admin)
    assert r.status_code == 409 and "disabled" in r.json()["detail"]
    assert client.post(f"{BASE}/instances/{inst['id']}/enable", headers=env.admin).status_code == 200
    assert client.post(url, headers=env.admin).status_code == 202


# ── delete ──────────────────────────────────────────────────────────────────


def test_delete_refused_while_targets_reference_it(env):
    inst = env.instance(env.iadmin, org=env.ours())
    t = env.target(f"ref-{hexid()}.example.com", verified=True, connector_instance_id=uuid.UUID(inst["id"]))
    url = f"{BASE}/instances/{inst['id']}"
    r = client.delete(url, headers=env.iadmin)
    assert r.status_code == 409 and r.json()["target_ids"] == [str(t.id)]
    assert "example.com" not in r.text  # ids only
    assert client.get(url, headers=env.iadmin).status_code == 200
    # reached: unreferenced, it goes
    env.db.delete(env.db.get(Target, t.id))
    env.db.commit()
    assert client.delete(url, headers=env.iadmin).status_code == 204
    assert client.get(url, headers=env.iadmin).status_code == 404


def test_delete_catches_the_database_refusal_too(env, monkeypatch):
    from app.api import connectors as api

    inst = env.instance(env.iadmin, org=env.ours())
    t = env.target(f"race-{hexid()}.example.com", verified=True, connector_instance_id=uuid.UUID(inst["id"]))
    real = api._referencing_targets
    calls = []

    def blind_once(db, instance_id):
        calls.append(1)
        return None if len(calls) == 1 else real(db, instance_id)

    monkeypatch.setattr(api, "_referencing_targets", blind_once)
    r = client.delete(f"{BASE}/instances/{inst['id']}", headers=env.iadmin)
    assert len(calls) == 2  # the explicit check was skipped, the FK refused, the handler re-queried
    assert r.status_code == 409 and r.json()["target_ids"] == [str(t.id)]
    assert client.get(f"{BASE}/instances/{inst['id']}", headers=env.iadmin).status_code == 200


# ── config ──────────────────────────────────────────────────────────────────


def test_config_masking_and_merge(env):
    inst = env.instance(env.iadmin, org=env.ours())
    url = f"{BASE}/instances/{inst['id']}/config"
    r = client.get(url, headers=env.iadmin)
    assert r.status_code == 200 and r.json()["config"] == {"api_token": "**configured**"} and TOKEN not in r.text
    r = client.put(url, headers=env.iadmin, json={"config": {"api_token": "**configured**", "excluded_zones": ["a.example.com"]}})
    assert r.status_code == 200 and r.json()["config"]["api_token"] == "**configured**"
    env.db.expire_all()
    stored = svc.decrypted_config(env.db.get(ConnectorInstance, uuid.UUID(inst["id"])))
    assert stored == {"api_token": TOKEN, "excluded_zones": ["a.example.com"]}
    # reached: a real new value does replace it
    client.put(url, headers=env.iadmin, json={"config": {"api_token": "tok-new"}})
    env.db.expire_all()
    assert svc.decrypted_config(env.db.get(ConnectorInstance, uuid.UUID(inst["id"])))["api_token"] == "tok-new"
    # the summary reports configured without the secret
    s = client.get(f"{BASE}/instances/{inst['id']}", headers=env.viewer)
    assert s.status_code == 200 and s.json()["configured"] is True and "tok-new" not in s.text
    # the viewer cannot read config
    assert client.get(url, headers=env.viewer).status_code == 403


def test_test_and_zones_use_the_instance_config(env, monkeypatch):
    calls = spy_cloudflare(monkeypatch, ["z1.example.com", "z2.example.com"])
    inst = env.instance(env.iadmin, org=env.ours())
    url = f"{BASE}/instances/{inst['id']}"
    assert client.put(f"{url}/zones", headers=env.iadmin, json={"excluded_zones": ["z2.example.com"]}).status_code == 200
    r = client.get(f"{url}/zones", headers=env.iadmin)
    assert r.json() == [{"name": "z1.example.com", "excluded": False}, {"name": "z2.example.com", "excluded": True}]
    assert calls[-1]["headers"]["Authorization"] == f"Bearer {TOKEN}"
    seen = []

    class _R:
        status_code = 200

        def json(self):
            return {"success": True}

    monkeypatch.setattr("app.connectors.cloudflare.httpx.get", lambda u, **kw: (seen.append(kw["headers"]), _R())[1])
    r = client.post(f"{url}/test", headers=env.iadmin)
    assert r.status_code == 200 and r.json()["success"] is True
    assert seen == [{"Authorization": f"Bearer {TOKEN}"}]
    # zones is a DNS-type route
    naabu = env.instance(env.iadmin, type="naabu", config={})
    assert client.get(f"{BASE}/instances/{naabu['id']}/zones", headers=env.iadmin).status_code == 400


# ── binding suggestion ──────────────────────────────────────────────────────


def _suggest(env, headers=None, type="cloudflare", **body):
    return client.post(f"{BASE}/{type}/binding-suggestion", headers=headers or env.iadmin,
                       json={"config": {"api_token": "tok-posted"}, **body})


def test_binding_suggestion(env, monkeypatch):
    org_a, org_b = env.ours(), env.ours()
    deal, eng = env.deal("pre_close")
    a1, a2, b1 = (f"{n}-{hexid()}.example.com" for n in ("a1", "a2", "b1"))
    c1, c2, c3 = (f"{n}-{hexid()}.example.com" for n in ("c1", "c2", "c3"))
    for org, v in ((org_a, a1), (org_a, a2), (org_b, b1), (deal, c1), (deal, c2), (deal, c3)):
        env.claim(org, v)
    # an OPEN candidate never counts
    open_value = f"open-{hexid()}.example.com"
    env.w.candidate(org_b, value=open_value)

    spy_cloudflare(monkeypatch, [a1, a2, b1])
    r = _suggest(env)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["suggested_entity_id"] == str(org_a.id) and body["zone_count"] == 3
    assert [(c["entity_id"], c["matches"]) for c in body["candidates"]] == [(str(org_a.id), 2), (str(org_b.id), 1)]

    # tie for first: no suggestion, both listed
    spy_cloudflare(monkeypatch, [a1, b1, open_value])
    body = _suggest(env).json()
    assert body["suggested_entity_id"] is None and {c["entity_id"] for c in body["candidates"]} == {str(org_a.id), str(org_b.id)}

    # no match
    spy_cloudflare(monkeypatch, [f"none-{hexid()}.example.com"])
    body = _suggest(env).json()
    assert body == {"suggested_entity_id": None, "candidates": [], "zone_count": 1}

    # a deal that has not closed is not suggested (and not revealed) even with more matches ...
    spy_cloudflare(monkeypatch, [a1, c1, c2, c3])
    body = _suggest(env).json()
    assert body["suggested_entity_id"] == str(org_a.id)
    assert str(deal.id) not in {c["entity_id"] for c in body["candidates"]}
    # ... reached: once it closes it wins
    env.set_posture(eng, "day_0")
    body = _suggest(env).json()
    assert body["suggested_entity_id"] == str(deal.id) and body["candidates"][0]["matches"] == 3

    # uppercase and a trailing dot still match
    spy_cloudflare(monkeypatch, [a1.upper() + ".", a2.upper()])
    body = _suggest(env).json()
    assert body["suggested_entity_id"] == str(org_a.id) and body["candidates"][0]["matches"] == 2

    # permission gate
    assert _suggest(env, headers=env.viewer).status_code == 403


def test_binding_suggestion_uses_stored_token_and_a_fixed_url(env, monkeypatch):
    org = env.ours()
    value = f"s-{hexid()}.example.com"
    env.claim(org, value)
    inst = env.instance(env.iadmin, org=org)
    calls = spy_cloudflare(monkeypatch, [value])

    r = _suggest(env, instance_id=inst["id"], config={"api_token": "**configured**", "base_url": "http://127.0.0.1:1"})
    assert r.status_code == 200 and r.json()["suggested_entity_id"] == str(org.id)
    assert calls[-1]["headers"]["Authorization"] == f"Bearer {TOKEN}"
    assert calls[-1]["url"].startswith("https://api.cloudflare.com/client/v4/zones")
    # reached: without instance_id the posted value is what is used
    _suggest(env, config={"api_token": "tok-typed"})
    assert calls[-1]["headers"]["Authorization"] == "Bearer tok-typed"
    # an instance of another type, or one that does not exist, is a 404
    wiz_like = env.instance(env.iadmin, type="naabu", config={})
    assert _suggest(env, instance_id=wiz_like["id"]).status_code == 404
    assert _suggest(env, instance_id=str(uuid.uuid4())).status_code == 404


def test_binding_suggestion_edge_types_and_failure(env, monkeypatch):
    r = client.post(f"{BASE}/wiz/binding-suggestion", headers=env.iadmin, json={"config": {}})
    assert r.status_code == 200 and r.json() == {"suggested_entity_id": None, "candidates": [], "zone_count": None}

    def boom(self, config):
        raise RuntimeError("upstream said token=SECRET-VALUE")

    monkeypatch.setattr(CloudflareConnector, "list_domains", boom)
    r = _suggest(env)
    assert r.status_code == 502 and "SECRET-VALUE" not in r.text and "tok-posted" not in r.text


# ── sync creates targets ────────────────────────────────────────────────────


def _patch_sync(monkeypatch, domains, discover=None):
    monkeypatch.setattr(CloudflareConnector, "list_domains", lambda self, config: list(domains))
    monkeypatch.setattr(CloudflareConnector, "discover", discover or (lambda self, d, config: PhaseResult()))


def _targets(env, *values):
    env.db.expire_all()
    return {t.value: t for t in env.db.query(Target).filter(Target.value.in_(values)).all()}


def test_sync_stamps_targets_with_the_instance_and_the_deal(env, monkeypatch):
    ours = env.ours()
    deal, eng = env.deal("day_0")
    other_org, other_eng = env.deal("pre_close")
    n = hexid()
    d_ours, d_deal, d_existing, d_plain = (f"{k}-{n}.example.com" for k in ("ours", "deal", "exist", "plain"))
    for v in (d_ours, d_deal, d_existing, d_plain):
        env.w.track_target(v)
    # a pre-existing, unverified target that belongs to ANOTHER engagement, and one under none
    env.target(d_existing, verified=False, engagement_id=other_eng.id)
    env.target(d_plain, verified=False)

    ours_inst = env.instance(env.admin, org=ours)
    deal_inst = env.instance(env.admin, org=deal)

    _patch_sync(monkeypatch, [d_ours])
    assert client.post(f"{BASE}/instances/{ours_inst['id']}/sync", headers=env.admin).status_code == 202
    t = _targets(env, d_ours)[d_ours]
    assert t.engagement_id is None and str(t.connector_instance_id) == ours_inst["id"] and t.verified is True
    assert t.verification_method == VerificationMethod.CONNECTOR

    d_same = f"same-{n}.example.com"
    env.target(d_same, verified=False, engagement_id=eng.id)
    _patch_sync(monkeypatch, [d_deal, d_existing, d_plain, d_same])
    assert client.post(f"{BASE}/instances/{deal_inst['id']}/sync", headers=env.admin).status_code == 202
    got = _targets(env, d_deal, d_existing, d_plain, d_same)
    assert got[d_deal].engagement_id == eng.id and str(got[d_deal].connector_instance_id) == deal_inst["id"]
    # an existing target of the SAME scope is adopted by the instance, never re-pointed
    assert got[d_same].engagement_id == eng.id and str(got[d_same].connector_instance_id) == deal_inst["id"]
    assert got[d_same].verified is True
    # a target of another scope (another deal, or the estate) is left untouched (zone clash: skipped)
    for v, eid in ((d_existing, other_eng.id), (d_plain, None)):
        assert got[v].engagement_id == eid and got[v].connector_instance_id is None and got[v].verified is False


def test_sync_one_failing_domain_does_not_stop_the_next(env, monkeypatch):
    org = env.ours()
    inst = env.instance(env.admin, org=org)
    n = hexid()
    bad, good = f"bad-{n}.example.com", f"good-{n}.example.com"
    env.w.track_target(bad)
    env.w.track_target(good)

    def discover(self, domain, config):
        return PhaseResult(assets=[DiscoveredAsset(asset_type="dns_record", value=domain)])

    def poisoning_writer(db, run_id, assets, target_ids=None, **kw):
        if assets[0].value == bad:
            db.execute(text("select 1/0"))  # a database error: aborts the transaction
        return None

    _patch_sync(monkeypatch, [bad, good], discover)
    monkeypatch.setattr("app.services.asset_writer.write_assets", poisoning_writer)
    assert client.post(f"{BASE}/instances/{inst['id']}/sync", headers=env.admin).status_code == 202
    got = _targets(env, bad, good)
    assert good in got and got[good].connector_instance_id is not None  # the session was usable after the failure
    assert bad not in got  # the failed domain's unit of work was rolled back whole


# ── bindable organizations (planning#284 slice D) ───────────────────────────


def _bindable(env, headers):
    r = client.get(f"{BASE}/bindable-organizations", headers=headers)
    assert r.status_code == 200, r.text
    return {o["id"]: o for o in r.json()}


def test_bindable_organizations_lists_ours_and_closed_deals_only(env):
    ours = env.ours()
    day0, _ = env.deal("day_0")
    pre_close, _ = env.deal("pre_close")
    plain = env.w.entity()  # a non-root entity: relationship is NULL
    listed = _bindable(env, env.iadmin)
    assert str(ours.id) in listed and listed[str(ours.id)]["posture"] is None
    assert listed[str(ours.id)]["relationship"] == "ours"
    assert str(day0.id) in listed and listed[str(day0.id)]["posture"] == "day_0"
    assert listed[str(day0.id)]["name"] == day0.legal_name
    assert str(pre_close.id) not in listed
    assert str(plain.id) not in listed


def test_bindable_organizations_follows_the_engagement_posture(env):
    deal, eng = env.deal("pre_close")
    assert str(deal.id) not in _bindable(env, env.admin)
    env.set_posture(eng, "integrated")
    assert _bindable(env, env.admin)[str(deal.id)]["posture"] == "integrated"


def test_bindable_organizations_needs_the_configure_permission(env):
    env.ours()
    assert client.get(f"{BASE}/bindable-organizations", headers=env.viewer).status_code == 403
    assert client.get(f"{BASE}/bindable-organizations", headers=env.iadmin).status_code == 200


def test_catalogue_flags_the_zone_capable_types(env):
    """`supports_zones` is the DNS-discovery capability the UI keys the Zones
    tab, sync and the binding suggestion on (not `phase`)."""
    r = client.get(f"{BASE}/", headers=env.iadmin)
    assert r.status_code == 200, r.text
    flags = {t["id"]: (t["supports_zones"], t["account_scoped"]) for t in r.json()}
    assert flags["cloudflare"] == (True, True)
    assert flags["wiz"] == (False, True)
    assert flags["shodan"] == (False, False)
    assert flags["certspotter"] == (False, False)
