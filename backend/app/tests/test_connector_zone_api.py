"""Slice C of planning#277 S1b: the zone-clash API, the connector decider on
the candidate API, and two regression tests for fixes made to
`connector_zones.process_zone` in review.

Real DB (the throwaway `constellus_test`), synthetic names only, the provider
transport patched. Every refusal also asserts the path was REACHED.

Run: backend/scripts/test.sh app/tests/test_connector_zone_api.py
"""

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.api.connectors import _auto_discover_all_domains
from app.main import app
from app.models.connector_zone_clash import ConnectorZoneClash
from app.models.evidence import EvidenceFetch
from app.models.scope_candidate import ScopeCandidate, ScopeSignal
from app.models.target import Target
from app.services.org_discovery import candidates as cand
from app.services.org_discovery import connector_zones as cz
from app.services.org_discovery import runner
from app.tests._entity_graph import cleanup_evidence
from app.tests._org_world import hexid
from app.tests.test_connector_fanout import make
from app.tests.test_connector_instance_api import BASE, ApiEnv, _patch_sync

# The rejected-during-sync test drives the real sync (conftest turns it off otherwise).
REAL_CONNECTOR_AUTOSYNC = True

client = TestClient(app)
ORGS = "/api/organizations"


@pytest.fixture
def env():
    e = ApiEnv()
    e.purge()
    yield e
    e.close()


@pytest.fixture
def followups(monkeypatch):
    monkeypatch.setattr(runner, "verify_after_claim", lambda cid: None)
    monkeypatch.setattr(runner, "verify_new_candidates", lambda ids: None)


def zone_name() -> str:
    return f"z-{hexid()}.example.com"


def add_clash(env, inst_id, zone, *, resolved=False, candidate_id=None, target_id=None) -> ConnectorZoneClash:
    now = datetime.now(timezone.utc)
    row = ConnectorZoneClash(
        id=uuid.uuid4(), instance_id=inst_id, zone=zone, reason="target_in_other_scope",
        conflicting_candidate_id=candidate_id, conflicting_target_id=target_id,
        first_seen_at=now, last_seen_at=now, resolved_at=now if resolved else None,
    )
    env.db.add(row)
    env.db.commit()
    return row


# ── clash endpoint ──────────────────────────────────────────────────────────


def test_zone_clashes_list_open_and_resolved(env):
    org = env.ours()
    inst = env.instance(env.admin, org=org)
    url = f"{BASE}/instances/{inst['id']}/zone-clashes"
    za, zb, zc = sorted([zone_name(), zone_name(), zone_name()])
    t = env.target(za, verified=False)
    open_a = add_clash(env, uuid.UUID(inst["id"]), za, target_id=t.id)
    resolved = add_clash(env, uuid.UUID(inst["id"]), zb, resolved=True)
    open_c = add_clash(env, uuid.UUID(inst["id"]), zc)

    r = client.get(url, headers=env.admin)
    assert r.status_code == 200, r.text
    rows = r.json()
    assert [x["id"] for x in rows] == [str(open_a.id), str(open_c.id)]  # reached: open ones listed
    assert rows[0]["zone"] == za and rows[0]["reason"] == "target_in_other_scope"
    assert rows[0]["conflicting_target_id"] == str(t.id) and rows[0]["resolved_at"] is None
    assert set(rows[0]) == {
        "id", "zone", "reason", "conflicting_candidate_id", "conflicting_target_id",
        "first_seen_at", "last_seen_at", "resolved_at",
    }

    r = client.get(url, params={"include_resolved": "true"}, headers=env.admin)
    assert [x["id"] for x in r.json()] == [str(open_a.id), str(open_c.id), str(resolved.id)]  # open first
    assert r.json()[2]["resolved_at"] is not None

    # the summary counts unresolved rows only
    assert client.get(f"{BASE}/instances/{inst['id']}", headers=env.admin).json()["open_zone_clashes"] == 2
    other = env.instance(env.admin, org=env.ours())
    assert other["open_zone_clashes"] == 0


def test_zone_clashes_read_scope_and_permission(env):
    ours = env.ours()
    deal, eng = env.deal("day_0")
    hidden = env.instance(env.admin, org=deal)
    own = env.instance(env.admin, org=ours)
    # reached: before the deal regresses the integration admin reads it
    assert client.get(f"{BASE}/instances/{hidden['id']}/zone-clashes", headers=env.iadmin).status_code == 200
    env.set_posture(eng, "pre_close")
    add_clash(env, uuid.UUID(hidden["id"]), zone_name())
    add_clash(env, uuid.UUID(own["id"]), zone_name())

    def get(headers, iid):
        return client.get(f"{BASE}/instances/{iid}/zone-clashes", headers=headers)

    # reached: the same caller reads the ours-bound instance's clash...
    assert len(get(env.iadmin, own["id"]).json()) == 1
    # ...but the deal-bound instance is closed to it: 404, not 403 and not an empty list
    assert get(env.iadmin, hidden["id"]).status_code == 404
    assert get(env.admin, hidden["id"]).status_code == 200
    assert get(env.viewer, hidden["id"]).status_code == 404
    assert get(env.admin, str(uuid.uuid4())).status_code == 404

    # Every role holds connectors.read (it is in _EVERYONE), so no persona can
    # be 403'd on it; the permission guard is exercised by the route-access
    # parity test. Unauthenticated callers never reach the route.
    assert client.get(f"{BASE}/instances/{own['id']}/zone-clashes").status_code in (401, 403)


def test_zone_clash_hides_a_conflict_the_caller_cannot_read(env):
    ours = env.ours()
    deal, eng = env.deal("day_0")
    inst = env.instance(env.admin, org=ours)
    url = f"{BASE}/instances/{inst['id']}/zone-clashes"
    za, zb = sorted([zone_name(), zone_name()])
    deal_target = env.target(za, verified=False, engagement_id=eng.id)
    estate_target = env.target(zb, verified=False)
    add_clash(env, uuid.UUID(inst["id"]), za, target_id=deal_target.id)
    add_clash(env, uuid.UUID(inst["id"]), zb, target_id=estate_target.id)

    def by_zone(headers):
        r = client.get(url, headers=headers)
        assert r.status_code == 200, r.text
        return {x["zone"]: x for x in r.json()}

    # reached: while the deal is open to everyone the integration admin sees the real row
    assert by_zone(env.iadmin)[za]["conflicting_target_id"] == str(deal_target.id)
    env.set_posture(eng, "pre_close")

    hidden = by_zone(env.iadmin)[za]
    assert hidden["reason"] == "conflict_not_visible"
    assert hidden["conflicting_target_id"] is None and hidden["conflicting_candidate_id"] is None
    # the row the caller may read is untouched, and the DB row keeps the real values
    visible = by_zone(env.iadmin)[zb]
    assert visible["reason"] == "target_in_other_scope" and visible["conflicting_target_id"] == str(estate_target.id)
    env.db.expire_all()
    assert env.db.query(ConnectorZoneClash).filter_by(instance_id=uuid.UUID(inst["id"]), zone=za).one().reason == (
        "target_in_other_scope"
    )

    real = by_zone(env.admin)[za]
    assert real["reason"] == "target_in_other_scope" and real["conflicting_target_id"] == str(deal_target.id)
    # an assignment on that engagement opens it
    scoped = env.scoped_to(eng)
    assert by_zone(scoped)[za]["conflicting_target_id"] == str(deal_target.id)
    # the summary count is unaffected
    assert client.get(f"{BASE}/instances/{inst['id']}", headers=env.iadmin).json()["open_zone_clashes"] == 2


# ── candidate API: who decided ──────────────────────────────────────────────


def test_candidate_detail_names_the_deciding_connector(env, followups):
    org = env.ours()
    inst = make(env, "cloudflare", org, "tok-o")
    z = zone_name()
    env.w.track_target(z)
    assert cz.process_zone(env.db, instance=inst, zone=z).action == cz.CLAIMED
    env.db.commit()
    c = env.db.query(ScopeCandidate).filter(ScopeCandidate.root_entity_id == org.id, ScopeCandidate.value == z).one()

    d = client.get(f"{ORGS}/candidates/{c.id}", headers=env.admin).json()
    assert d["status"] == "claimed"  # reached
    assert d["decided_by_connector_instance_id"] == str(inst.id) and d["decided_by_id"] is None
    assert d["decided_by_connector_name"] == inst.name
    (claimed,) = [e for e in d["events"] if e["event"] == "claimed"]
    assert claimed["connector_instance_id"] == str(inst.id) and claimed["user_id"] is None

    # the name is looked up now, never stored
    r = client.patch(f"{BASE}/instances/{inst.id}", headers=env.admin, json={"name": f"renamed-{hexid()}"})
    assert r.status_code == 200, r.text
    new_name = r.json()["name"]
    d = client.get(f"{ORGS}/candidates/{c.id}", headers=env.admin).json()
    assert d["decided_by_connector_name"] == new_name != inst.name

    # the list row carries the id only
    rows = client.get(f"{ORGS}/{org.id}/candidates", headers=env.admin, params={"status": "claimed"})
    assert rows.status_code == 200, rows.text
    body = rows.json()
    items = body["items"]
    mine = [x for x in items if x["id"] == str(c.id)]
    assert mine and mine[0]["decided_by_connector_instance_id"] == str(inst.id)
    assert "decided_by_connector_name" not in mine[0]


def test_candidate_detail_hides_the_connector_name_from_a_caller_who_cannot_read_it(env, followups):
    deal, eng = env.deal("day_0")
    inst = make(env, "cloudflare", deal, "tok-d")
    z = zone_name()
    env.w.track_target(z)
    assert cz.process_zone(env.db, instance=inst, zone=z).action == cz.CLAIMED
    env.db.commit()
    c = env.db.query(ScopeCandidate).filter(ScopeCandidate.root_entity_id == deal.id, ScopeCandidate.value == z).one()
    d = client.get(f"{ORGS}/candidates/{c.id}", headers=env.iadmin).json()
    assert d["decided_by_connector_name"] == inst.name  # reached: a reader sees the name
    env.set_posture(eng, "pre_close")
    r = client.get(f"{ORGS}/candidates/{c.id}", headers=env.iadmin)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["decided_by_connector_instance_id"] == str(inst.id)
    assert d["decided_by_connector_name"] is None


def test_candidate_detail_of_a_person_claim_has_no_connector(env):
    org = env.ours()
    z = zone_name()
    c = env.claim(org, z)
    user = env.w.user()
    env.db.execute(ScopeCandidate.__table__.update().where(ScopeCandidate.id == c.id).values(decided_by_id=user.id))
    env.db.commit()
    d = client.get(f"{ORGS}/candidates/{c.id}", headers=env.admin).json()
    assert d["status"] == "claimed" and d["decided_by_id"] == str(user.id)
    assert d["decided_by_connector_instance_id"] is None and d["decided_by_connector_name"] is None


# ── reviewer fixes in process_zone ──────────────────────────────────────────


def test_target_attributed_to_a_subsidiary_in_the_tree_is_not_a_clash(env, followups):
    org, other = env.ours(), env.ours()
    sub = env.w.child_of(org)
    inst = make(env, "cloudflare", org, "tok-o")
    z_in, z_out = zone_name(), zone_name()
    t_in = env.target(z_in, verified=False, entity_id=sub.id)
    env.target(z_out, verified=False, entity_id=other.id)

    out = cz.process_zone(env.db, instance=inst, zone=z_in)
    env.db.commit()
    assert out.action in (cz.CLAIMED, cz.ALREADY_CLAIMED)
    assert env.db.query(ConnectorZoneClash).filter(
        ConnectorZoneClash.instance_id == inst.id, ConnectorZoneClash.zone == z_in
    ).count() == 0
    env.db.expire_all()
    got = env.db.get(Target, t_in.id)
    assert got.verified is True and got.connector_instance_id == inst.id and got.entity_id == sub.id

    # contrast (reached): outside the tree is still a clash
    assert cz.process_zone(env.db, instance=inst, zone=z_out).action == cz.CLASH
    env.db.commit()
    (row,) = env.db.query(ConnectorZoneClash).filter(
        ConnectorZoneClash.instance_id == inst.id, ConnectorZoneClash.zone == z_out
    ).all()
    assert row.reason == "target_other_entity"


def test_candidate_rejected_during_the_sync_rolls_the_zone_back(env, followups, monkeypatch):
    org = env.ours()
    inst = make(env, "cloudflare", org, "tok-o")
    z = zone_name()
    env.w.track_target(z)
    person = env.w.user()
    reached = []
    real = cand.record_signal

    def record_then_reject(db, **kw):
        out = real(db, **kw)
        if kw.get("signal_type") == "connector_zone":
            cand._reject_locked(db, out.candidate, user=person, reason="not ours")
            reached.append(out.candidate.id)
        return out

    monkeypatch.setattr(cand, "record_signal", record_then_reject)
    try:
        # directly: process_zone raises, and the caller's rollback leaves nothing
        with pytest.raises(cand.CandidateConflict):
            cz.process_zone(env.db, instance=inst, zone=z)
        env.db.rollback()
        assert len(reached) == 1  # the wrapper ran: the rejection really happened mid-call
        _assert_nothing_left(env, org, inst, z)

        # through the sync: the zone is rolled back, not committed
        _patch_sync(monkeypatch, [z])
        monkeypatch.setattr(cand, "record_signal", record_then_reject)
        _auto_discover_all_domains(inst.id)
        assert len(reached) == 2
        _assert_nothing_left(env, org, inst, z)
    finally:
        monkeypatch.undo()
        env.db.rollback()
        for (fid,) in env.db.query(EvidenceFetch.id).filter(
            EvidenceFetch.source_url.like(f"%/connector_zone/{inst.id}/%")
        ).all():
            cleanup_evidence(env.db, fid)


def _assert_nothing_left(env, org, inst, z):
    env.db.expire_all()
    t = env.db.query(Target).filter(Target.value == z).one_or_none()
    assert t is None or (t.verified is not True and t.connector_instance_id is None)
    assert env.db.query(ScopeSignal).join(ScopeCandidate, ScopeCandidate.id == ScopeSignal.candidate_id).filter(
        ScopeCandidate.root_entity_id == org.id, ScopeCandidate.value == z,
        ScopeSignal.signal_type == "connector_zone",
    ).count() == 0
    c = env.db.query(ScopeCandidate).filter(ScopeCandidate.root_entity_id == org.id, ScopeCandidate.value == z).one_or_none()
    assert c is None or c.status != "claimed"
