"""An active connector zone verifies its target and claims its candidate
(planning#277 S1b slice B): `connector_zones.process_zone`,
`candidates.claim_by_connector`, the sync that drives them, and the
create/rebind triggers.

Real DB (the throwaway `constellus_test`), synthetic names only, the provider
transport patched (never a network call), the org-discovery follow-ups
replaced by recorders. Every "did not happen" assertion also asserts the path
that stops it was REACHED (the clash row, the expected outcome action).

Run: backend/scripts/test.sh app/tests/test_connector_zones.py
"""

import uuid

import pytest
from fastapi.testclient import TestClient

from app.api.connectors import _auto_discover_all_domains
from app.connectors.base import DiscoveredAsset, PhaseResult
from app.connectors.cloudflare import CloudflareConnector
from app.main import app
from app.models.connector_zone_clash import ConnectorZoneClash
from app.models.scope_candidate import ScopeCandidate, ScopeCandidateEvent, ScopeSignal
from app.models.target import Target, TargetType, VerificationMethod
from app.services.org_discovery import candidates as cand
from app.services.org_discovery import connector_zones as cz
from app.services.org_discovery import runner
from app.tests._org_world import hexid
from app.tests.test_connector_fanout import make
from app.tests.test_connector_instance_api import BASE, ApiEnv, _patch_sync

# These tests exercise the create/rebind sync trigger for real (conftest turns it off otherwise).
REAL_CONNECTOR_AUTOSYNC = True

client = TestClient(app)


@pytest.fixture
def env():
    e = ApiEnv()
    e.purge()
    yield e
    e.close()


@pytest.fixture
def followups(monkeypatch):
    calls = {"claimed": [], "new": []}
    monkeypatch.setattr(runner, "verify_after_claim", lambda cid: calls["claimed"].append(cid))
    monkeypatch.setattr(runner, "verify_new_candidates", lambda ids: calls["new"].append(list(ids)))
    return calls


def zone_name() -> str:
    return f"z-{hexid()}.example.com"


def run_zone(env, inst, zone):
    out = cz.process_zone(env.db, instance=inst, zone=zone)
    env.db.commit()
    env.db.expire_all()
    return out


def cand_of(env, org, value) -> ScopeCandidate | None:
    env.db.expire_all()
    return env.db.query(ScopeCandidate).filter(
        ScopeCandidate.root_entity_id == org.id, ScopeCandidate.value == value
    ).one_or_none()


def clashes(env, inst, zone=None, open_only=True):
    env.db.expire_all()
    q = env.db.query(ConnectorZoneClash).filter(ConnectorZoneClash.instance_id == inst.id)
    if zone:
        q = q.filter(ConnectorZoneClash.zone == zone)
    if open_only:
        q = q.filter(ConnectorZoneClash.resolved_at.is_(None))
    return q.all()


def signals(env, candidate_id):
    env.db.expire_all()
    return env.db.query(ScopeSignal).filter(ScopeSignal.candidate_id == candidate_id).all()


def events(env, candidate_id, name=None):
    env.db.expire_all()
    q = env.db.query(ScopeCandidateEvent).filter(ScopeCandidateEvent.candidate_id == candidate_id)
    if name:
        q = q.filter(ScopeCandidateEvent.event == name)
    return q.all()


def target_of(env, value) -> Target | None:
    env.db.expire_all()
    return env.db.query(Target).filter(Target.value == value).one_or_none()


# ── the claim ───────────────────────────────────────────────────────────────


def test_ours_bound_new_zone_verifies_and_claims(env, followups, monkeypatch):
    org = env.ours()
    inst = make(env, "cloudflare", org, "tok-o")
    z = zone_name()
    env.w.track_target(z)
    monkeypatch.setattr(CloudflareConnector, "list_domains", lambda self, config: [z])
    monkeypatch.setattr(CloudflareConnector, "discover", lambda self, d, config: PhaseResult(
        assets=[DiscoveredAsset(asset_type="dns_record", value=d)]))
    _auto_discover_all_domains(inst.id)

    t = target_of(env, z)
    assert t.verified is True and t.verification_method == VerificationMethod.CONNECTOR
    assert t.connector_instance_id == inst.id and t.entity_id == org.id and t.engagement_id is None
    c = cand_of(env, org, z)
    assert c.status == "claimed" and c.decided_by_connector_instance_id == inst.id and c.decided_by_id is None
    assert c.accepted_into == "estate" and c.engagement_id is None and c.target_id == t.id
    assert c.affiliated_entity_id == org.id
    ev = events(env, c.id)
    assert [(e.event, e.connector_instance_id, e.user_id) for e in ev] == [("claimed", inst.id, None)]
    sig = signals(env, c.id)
    assert len(sig) == 1 and sig[0].signal_type == "connector_zone" and sig[0].anchor_kind == "connector_instance"
    assert sig[0].anchor_connector_instance_id == inst.id
    assert followups["claimed"] == [c.id] and followups["new"] == []
    assert clashes(env, inst) == []


def test_deal_bound_zone_claims_into_the_engagement(env, followups):
    deal, eng = env.deal("day_0")
    inst = make(env, "cloudflare", deal, "tok-d")
    z = zone_name()
    env.w.track_target(z)
    out = run_zone(env, inst, z)
    assert out.action == cz.CLAIMED and out.claimed
    t = target_of(env, z)
    assert t.engagement_id == eng.id and t.entity_id == deal.id
    c = cand_of(env, deal, z)
    assert c.status == "claimed" and c.accepted_into == "engagement" and c.engagement_id == eng.id
    assert c.target_id == t.id and c.decided_by_connector_instance_id == inst.id


def test_resync_keeps_one_evidence_one_signal_one_claim(env, followups):
    org = env.ours()
    inst = make(env, "cloudflare", org, "tok-o")
    z = zone_name()
    env.w.track_target(z)
    first = run_zone(env, inst, z)
    assert first.action == cz.CLAIMED
    c = cand_of(env, org, z)
    s1 = signals(env, c.id)[0]
    seen1, evidence1, target1 = s1.last_seen_at, s1.evidence_id, c.target_id

    second = run_zone(env, inst, z)
    assert second.action == cz.ALREADY_CLAIMED and second.target is not None and not second.claimed
    s = signals(env, c.id)
    assert len(s) == 1 and s[0].id == s1.id and s[0].evidence_id == evidence1
    assert s[0].last_seen_at > seen1
    assert len(events(env, c.id, "claimed")) == 1
    assert cand_of(env, org, z).target_id == target1


# ── clashes ─────────────────────────────────────────────────────────────────


def test_zone_claimed_by_another_org_clashes_and_touches_nothing(env, followups):
    org, other = env.ours(), env.ours()
    inst = make(env, "cloudflare", org, "tok-o")
    z = zone_name()
    env.w.track_target(z)
    theirs = env.claim(other, z)
    out = run_zone(env, inst, z)
    assert out.action == cz.CLASH and out.candidate_id == theirs.id
    (row,) = clashes(env, inst, z)
    assert row.reason == "claimed_by_other_org" and row.conflicting_candidate_id == theirs.id
    assert target_of(env, z) is None
    assert cand_of(env, org, z) is None  # nothing under the instance's root, so no signal either
    assert cand_of(env, other, z).status == "claimed"
    assert followups["claimed"] == []


def test_target_in_other_scope_clashes_and_is_untouched(env, followups):
    org = env.ours()
    deal, eng = env.deal("day_0")
    inst = make(env, "cloudflare", org, "tok-o")
    z = zone_name()
    t = env.target(z, verified=False, engagement_id=eng.id)
    out = run_zone(env, inst, z)
    assert out.action == cz.CLASH
    (row,) = clashes(env, inst, z)
    assert row.reason == "target_in_other_scope" and row.conflicting_target_id == t.id
    got = target_of(env, z)
    assert (got.verified, got.connector_instance_id, got.engagement_id, got.entity_id) == (False, None, eng.id, None)
    assert cand_of(env, org, z) is None
    # the scope check runs read-only BEFORE store_evidence (which commits): no
    # evidence row that no signal cites
    from app.models.evidence import EvidenceFetch

    prefix = f"https://org-discovery.invalid/generate/connector_zone/{inst.id}/"
    assert env.db.query(EvidenceFetch).filter(EvidenceFetch.source_url.startswith(prefix)).count() == 0


def test_target_attributed_to_another_entity_clashes_and_is_untouched(env, followups):
    org, other = env.ours(), env.ours()
    inst = make(env, "cloudflare", org, "tok-o")
    z = zone_name()
    t = env.target(z, verified=False, entity_id=other.id)
    out = run_zone(env, inst, z)
    assert out.action == cz.CLASH
    (row,) = clashes(env, inst, z)
    assert row.reason == "target_other_entity" and row.conflicting_target_id == t.id
    got = target_of(env, z)
    assert (got.verified, got.connector_instance_id, got.entity_id) == (False, None, other.id)
    assert cand_of(env, org, z) is None


def test_a_clash_is_one_row_that_resolves_when_the_conflict_goes(env, followups):
    org = env.ours()
    deal, eng = env.deal("day_0")
    inst = make(env, "cloudflare", org, "tok-o")
    z = zone_name()
    t = env.target(z, verified=False, engagement_id=eng.id)
    assert run_zone(env, inst, z).action == cz.CLASH
    first = clashes(env, inst, z)[0]
    assert run_zone(env, inst, z).action == cz.CLASH
    (again,) = clashes(env, inst, z)  # still exactly one open row
    assert again.id == first.id and again.last_seen_at >= first.last_seen_at

    env.db.delete(env.db.get(Target, t.id))
    env.db.commit()
    out = run_zone(env, inst, z)
    assert out.action == cz.CLAIMED
    assert clashes(env, inst, z) == []
    (resolved,) = clashes(env, inst, z, open_only=False)
    assert resolved.id == first.id and resolved.resolved_at is not None
    assert cand_of(env, org, z).status == "claimed"


def test_a_zone_dropped_from_the_listing_resolves_its_clash(env, followups, monkeypatch):
    org = env.ours()
    deal, eng = env.deal("day_0")
    inst = make(env, "cloudflare", org, "tok-o")
    keep, drop = zone_name(), zone_name()
    env.target(keep, verified=False, engagement_id=eng.id)
    env.target(drop, verified=False, engagement_id=eng.id)
    _patch_sync(monkeypatch, [keep, drop])
    _auto_discover_all_domains(inst.id)
    assert {c.zone for c in clashes(env, inst)} == {keep, drop}  # reached: both clashed

    _patch_sync(monkeypatch, [keep])
    _auto_discover_all_domains(inst.id)
    assert {c.zone for c in clashes(env, inst)} == {keep}
    (dropped,) = clashes(env, inst, drop, open_only=False)
    assert dropped.resolved_at is not None
    assert cz.resolve_unlisted(env.db, instance=inst, listed={keep}) == 0  # idempotent


# ── a person's rejection outranks the connector ─────────────────────────────


def test_a_rejected_candidate_is_never_verified_or_claimed(env, followups, monkeypatch):
    org = env.ours()
    inst = make(env, "cloudflare", org, "tok-o")
    z = zone_name()
    env.w.track_target(z)
    seeded = env.w.candidate(org, value=z)
    cand.reject(env.db, candidate_id=seeded.id, user=env.w.user(), reason="not ours")

    out = run_zone(env, inst, z)
    assert out.action == cz.SIGNAL_ONLY_REJECTED and out.target is None and not out.claimed
    c = cand_of(env, org, z)
    types = {s.signal_type for s in signals(env, c.id)}
    assert types == {"person_evidence", "connector_zone"}  # reached: the signal was recorded
    assert target_of(env, z) is None
    assert c.status != "claimed" and c.decided_by_connector_instance_id is None
    assert len(events(env, c.id, "claimed")) == 0 and len(events(env, c.id, "rejected")) == 1

    # the new Strong signal reopened it (record_signal's own unlock); the NEXT sync still does not claim it
    assert c.status == "open" and out.left_open
    again = run_zone(env, inst, z)
    assert again.action == cz.SIGNAL_ONLY_REJECTED and target_of(env, z) is None
    assert cand_of(env, org, z).status == "open"

    # through the sync: follow-up is verify_new_candidates, never verify_after_claim
    monkeypatch.setattr(CloudflareConnector, "list_domains", lambda self, config: [z])
    _auto_discover_all_domains(inst.id)
    assert followups["claimed"] == [] and followups["new"] == [[c.id]]


# ── claim_by_connector refusals ─────────────────────────────────────────────


def _signalled(env, inst, org, value):
    """An open candidate with a connector_zone signal from `inst`, as the
    service writes it (but not yet claimed)."""
    ev = env.w.evidence_row("zone")
    out = cand.record_signal(
        env.db, root_entity_id=org.id, value=value, signal_type="connector_zone",
        anchor_kind="connector_instance", anchor_connector_instance_id=inst.id, via_entity_id=org.id,
        evidence_id=ev.id, quote=f"{value} is an active zone in connector instance {inst.id}",
    )
    env.db.commit()
    return out.candidate


def _estate_target(env, value):
    env.w.track_target(value)
    t = Target(id=uuid.uuid4(), type=TargetType.DOMAIN, value=value, verified=True)
    env.db.add(t)
    env.db.commit()
    return t


def test_claim_by_connector_refusals(env, followups):
    org, other = env.ours(), env.ours()
    deal, eng = env.deal("day_0")
    inst = make(env, "cloudflare", org, "tok-o")
    inst2 = make(env, "cloudflare", org, "tok-o2")
    z = zone_name()
    c = _signalled(env, inst, org, z)
    t = _estate_target(env, z)

    # not open
    claimed = env.claim(org, zone_name())
    with pytest.raises(cand.CandidateConflict):
        cand.claim_by_connector(env.db, candidate=claimed, instance=inst, target=t)
    env.db.rollback()
    # root mismatch
    foreign = env.w.candidate(other, value=zone_name())
    with pytest.raises(cand.CandidateConflict):
        cand.claim_by_connector(env.db, candidate=foreign, instance=inst, target=t)
    env.db.rollback()
    # target scope != instance scope
    deal_target = Target(id=uuid.uuid4(), type=TargetType.DOMAIN, value=z, engagement_id=eng.id)
    with pytest.raises(cand.CandidateConflict):
        cand.claim_by_connector(env.db, candidate=c, instance=inst, target=deal_target)
    env.db.rollback()
    # no connector_zone signal from THIS instance (a person's signal, and another instance's)
    plain = env.w.candidate(org, value=zone_name())
    with pytest.raises(RuntimeError):
        cand.claim_by_connector(env.db, candidate=plain, instance=inst, target=t)
    env.db.rollback()
    with pytest.raises(RuntimeError):
        cand.claim_by_connector(env.db, candidate=c, instance=inst2, target=t)
    env.db.rollback()

    # reached: every refusal left the candidate open, and the valid call claims it
    assert cand_of(env, org, z).status == "open"
    c = cand_of(env, org, z)
    cand.claim_by_connector(env.db, candidate=c, instance=inst, target=t)
    env.db.commit()
    got = cand_of(env, org, z)
    assert got.status == "claimed" and got.decided_by_connector_instance_id == inst.id and got.target_id == t.id


# ── create / rebind trigger the sync ────────────────────────────────────────


def test_create_instance_queues_the_sync(env, followups, monkeypatch):
    org = env.ours()
    z = zone_name()
    env.w.track_target(z)
    _patch_sync(monkeypatch, [z])
    env.instance(env.admin, org=org)
    assert cand_of(env, org, z).status == "claimed"
    assert target_of(env, z).entity_id == org.id


def test_create_unconfigured_instance_does_not_sync(env, followups, monkeypatch):
    org = env.ours()
    calls = []
    monkeypatch.setattr(CloudflareConnector, "list_domains", lambda self, config: calls.append(1) or [])
    env.instance(env.admin, org=org, config={})
    assert calls == []


def test_rename_does_not_sync_but_rebind_does(env, followups, monkeypatch):
    org, org2 = env.ours(), env.ours()
    inst = env.instance(env.admin, org=org)  # list_domains unpatched here: would hit the network if it ran
    calls = []
    z = zone_name()
    env.w.track_target(z)

    def listing(self, config):
        calls.append(1)
        return [z]

    monkeypatch.setattr(CloudflareConnector, "list_domains", listing)
    monkeypatch.setattr(CloudflareConnector, "discover", lambda self, d, config: PhaseResult())
    r = client.patch(f"{BASE}/instances/{inst['id']}", headers=env.admin, json={"name": f"conn284-{hexid()}"})
    assert r.status_code == 200, r.text
    assert calls == [] and cand_of(env, org, z) is None  # reached: PATCH succeeded, nothing synced

    r = client.patch(f"{BASE}/instances/{inst['id']}", headers=env.admin, json={"bound_entity_id": str(org2.id)})
    assert r.status_code == 200, r.text
    assert calls == [1]
    assert cand_of(env, org2, z).status == "claimed"


# ── security review: canonical form, race, posture ─────────────────────────


def _evidence_count(env, inst) -> int:
    from app.models.evidence import EvidenceFetch

    prefix = f"https://org-discovery.invalid/generate/connector_zone/{inst.id}/"
    return env.db.query(EvidenceFetch).filter(EvidenceFetch.source_url.startswith(prefix)).count()


def test_www_zone_is_not_a_claimable_domain_and_never_claims_the_apex(env, followups):
    org, other = env.ours(), env.ours()
    inst = make(env, "cloudflare", org, "tok-o")
    apex = zone_name()
    env.w.track_target(apex)
    env.w.track_target(f"www.{apex}")
    theirs = env.claim(other, apex)
    out = run_zone(env, inst, f"www.{apex}")
    assert out.action == cz.CLASH  # reached
    (row,) = clashes(env, inst)
    assert row.reason == "not_a_claimable_domain" and row.zone == f"www.{apex}"
    assert row.conflicting_candidate_id is None and row.conflicting_target_id is None
    assert target_of(env, apex) is None and target_of(env, f"www.{apex}") is None
    assert cand_of(env, org, apex) is None and cand_of(env, org, f"www.{apex}") is None
    assert _evidence_count(env, inst) == 0
    assert cand_of(env, other, apex).id == theirs.id and cand_of(env, other, apex).status == "claimed"
    assert followups["claimed"] == []


def test_non_hostname_zone_is_not_a_claimable_domain(env, followups):
    org = env.ours()
    inst = make(env, "cloudflare", org, "tok-o")
    out = run_zone(env, inst, "bad_zone!.example")
    assert out.action == cz.CLASH
    (row,) = clashes(env, inst)
    assert row.reason == "not_a_claimable_domain" and row.zone == "bad_zone!.example"
    assert target_of(env, "bad_zone!.example") is None and _evidence_count(env, inst) == 0
    assert env.db.query(ScopeCandidate).filter(ScopeCandidate.root_entity_id == org.id).count() == 0
    with pytest.raises(ValueError):
        cz.process_zone(env.db, instance=inst, zone="  ")
    env.db.rollback()


def test_a_normal_zone_still_claims_after_the_canonical_gate(env, followups):
    org = env.ours()
    inst = make(env, "cloudflare", org, "tok-o")
    z = zone_name()
    env.w.track_target(z)
    assert run_zone(env, inst, z.upper()).action == cz.CLAIMED  # case/trailing dot canonicalise, no clash
    assert clashes(env, inst) == [] and cand_of(env, org, z).status == "claimed"


def test_target_attributed_between_check_and_write_is_not_overwritten(env, followups, monkeypatch):
    from app.core.database import SessionLocal

    org, outsider = env.ours(), env.ours()
    inst = make(env, "cloudflare", org, "tok-o")
    z = zone_name()
    t = env.target(z, verified=False)  # estate, unattributed: passes the first (read-only) check
    ran = []
    real = cz._store_zone_evidence

    def racing(db, *, instance, value):
        ev = real(db, instance=instance, value=value)
        other = SessionLocal()
        try:
            other.query(Target).filter(Target.id == t.id).update({"entity_id": outsider.id})
            other.commit()
        finally:
            other.close()
        ran.append(1)
        return ev

    monkeypatch.setattr(cz, "_store_zone_evidence", racing)
    out = run_zone(env, inst, z)
    assert ran == [1]  # reached: the other session committed between the checks and the writes
    assert out.action == cz.CLASH
    (row,) = clashes(env, inst, z)
    assert row.reason == "target_other_entity" and row.conflicting_target_id == t.id
    got = target_of(env, z)
    assert got.entity_id == outsider.id and got.verified is False and got.connector_instance_id is None
    assert cand_of(env, org, z) is None  # no connector_zone signal, so no candidate under this root
    assert followups["claimed"] == []


def test_sync_stops_when_the_binding_is_refused_mid_run(env, followups, monkeypatch):
    from app.services import connector_instances as svc

    org = env.ours()
    inst = make(env, "cloudflare", org, "tok-o")
    z1, z2 = sorted([zone_name(), zone_name()])
    env.w.track_target(z1)
    env.w.track_target(z2)
    monkeypatch.setattr(CloudflareConnector, "list_domains", lambda self, config: [z1, z2])
    monkeypatch.setattr(CloudflareConnector, "discover", lambda self, d, config: PhaseResult())
    real = svc.binding_allowed
    calls = []

    def flaky(db, entity_id):
        calls.append(1)
        return real(db, entity_id) if len(calls) <= 2 else (False, "refused")  # start check + first zone

    monkeypatch.setattr(svc, "binding_allowed", flaky)
    _auto_discover_all_domains(inst.id)
    assert len(calls) == 3  # reached: the third call (second zone) refused
    assert cand_of(env, org, z1).status == "claimed"
    assert cand_of(env, org, z2) is None and target_of(env, z2) is None


def test_sync_stops_when_the_instance_is_disabled_mid_run(env, followups, monkeypatch):
    org = env.ours()
    inst = make(env, "cloudflare", org, "tok-o")
    z1, z2 = sorted([zone_name(), zone_name()])
    env.w.track_target(z1)
    env.w.track_target(z2)
    monkeypatch.setattr(CloudflareConnector, "list_domains", lambda self, config: [z1, z2])

    def discover(self, d, config):
        from app.core.database import SessionLocal
        from app.models.connector_instance import ConnectorInstance

        other = SessionLocal()
        try:
            other.query(ConnectorInstance).filter(ConnectorInstance.id == inst.id).update({"enabled": False})
            other.commit()
        finally:
            other.close()
        return PhaseResult()

    monkeypatch.setattr(CloudflareConnector, "discover", discover)
    _auto_discover_all_domains(inst.id)
    assert cand_of(env, org, z1).status == "claimed"  # reached: the first zone ran
    assert cand_of(env, org, z2) is None
