"""The attribution chain builder (planning#358), called directly as an admin.

Read scope (hidden rows, permission gates) is spec 2's; every test here reads
as an admin so what is under test is the chain itself: which hops, in which
order, with which statuses, reasons, tiers and evidence rows.

The world is real rows. Assets go through `write_assets` (the exposure-path
test's `_World`); entities, relations and engagements through `_org_world.World`;
claims through `claim_emitter.upsert_single_claim`, and the estate through the
real projector. Two things are inserted directly because no producer runs here:
claimed scope candidates with their signals (following migration 0083's CHECKs),
and `target_asset_links`.

Synthetic data only: `example.org` / `example.net` names with a module-unique
label, `Example Holdings ...` entities, addresses `_a(0)`..`_a(3)` of
test_exposure_path.py.

Run with:  backend/scripts/test.sh app/tests/test_attribution_chain.py
"""

import threading
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import true

from app.connectors.base import DiscoveredAsset
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.claim import AssetClaim
from app.models.entity_relation import EntityRelation
from app.models.observer import OBSERVER_TRUST, Observer
from app.models.scope_candidate import ScopeCandidate, ScopeSignal
from app.models.target import Target
from app.models.target_asset_link import TargetAssetLink
from app.services import attribution_chain, attribution_tiers, claim_emitter, dns_walk, entity_graph, projector
from app.services.org_discovery import tiers
from app.services.attribution_chain import (
    _CLAIMED,
    _DERIVED_BY_NAME,
    _DERIVED_BY_PARENT,
    _DERIVED_BY_RANGE,
    _DERIVED_NAMES_ABOVE_ADDRESS,
    _DERIVED_NAMES_ABOVE_HOST,
    _NO_NAME_ABOVE_ADDRESS,
    _NO_ORG_ABOVE_ENTITY,
    _NO_ORG_ON_TARGET,
    _NO_OWNERSHIP_CHECK,
    _NO_TARGET,
    _NO_TARGET_ORG,
    _NOT_OURS_THIRD_PARTY,
    _SCOPE_NO_CANDIDATE,
    _WALK_CUT_SHORT,
    build_attribution,
)
from app.tests._entity_graph import cleanup_observer, make_evidence, make_observer
from app.tests._org_world import World
from app.tests.test_exposure_path import _a, _World

T0 = datetime(2020, 1, 1, 12, 0, tzinfo=timezone.utc)
T1 = T0 + timedelta(days=1)
T2 = T0 + timedelta(days=2)

_LABEL = f"ac-{uuid.uuid4().hex[:8]}"
_DOM = f"{_LABEL}.example.org"
_QUOTE_MARKER = "QUOTEMARKER-" + uuid.uuid4().hex[:8]
_MATCH_MARKER = "MATCHMARKER-" + uuid.uuid4().hex[:8]


def _host(label: str = "www") -> str:
    return f"{label}.{_DOM}"


class _Env:
    def __init__(self):
        self.w = World()
        self.xw = _World()
        self.db = self.xw.db
        self.admin = self.w.user()
        self.observer_ids: list[uuid.UUID] = []

    # -- assets and claims -----------------------------------------------------

    def assets(self, *, addresses=(), records=()):
        self.xw.assets(addresses=list(addresses), records=list(records))
        self.db.expire_all()
        for value in list(addresses) + sorted({r[0] for r in records}):
            self.clear_claims(self.asset(value))

    def asset(self, value: str) -> AssetCanonical:
        self.db.expire_all()
        return self.db.query(AssetCanonical).filter(AssetCanonical.value == value).one()

    def clear_claims(self, asset: AssetCanonical) -> None:
        self.db.rollback()
        self.db.query(AssetClaim).filter(AssetClaim.asset_canonical_id == asset.id).delete(synchronize_session=False)
        self.db.commit()

    def claim(self, asset, observer: str, claim_type: str, value: dict | None = None, at: datetime = T0) -> None:
        row = claim_emitter.upsert_single_claim(self.db, asset.id, observer, claim_type, value or {}, at)
        assert row is not None, f"observer {observer!r} is not seeded"
        self.db.commit()

    def throwaway_observer(self, trust: str = "observed") -> str:
        o = make_observer(self.db, trust=trust, name=f"ac358-{uuid.uuid4().hex[:8]}")
        self.observer_ids.append(o.id)
        return o.name

    def project(self, *assets) -> None:
        projector.project(self.db, {a.id for a in assets}, T2)
        self.db.commit()

    # -- targets ---------------------------------------------------------------

    def target(self, value: str, ttype: str = "domain", entity=None, created: datetime | None = None) -> Target:
        self.db.rollback()
        self.db.query(Target).filter(Target.value == value).delete(synchronize_session=False)
        self.db.commit()
        kw = {"created_at": created} if created is not None else {}
        t = Target(type=ttype, value=value, verified=True, verification_method="manual",
                   entity_id=entity.id if entity is not None else None, **kw)
        self.db.add(t)
        self.db.commit()
        self.w.track_target(value)
        return t

    def link(self, target: Target, asset: AssetCanonical, first=T0, last=T1) -> None:
        self.db.add(TargetAssetLink(
            target_id=target.id, asset_canonical_id=asset.id, first_linked_at=first, last_observed_at=last))
        self.db.commit()

    def claimed_candidate(self, root, target: Target, signals: list[tuple[str, str | None]]) -> ScopeCandidate:
        """A claimed domain candidate for `target`, with one signal per
        (signal_type, observer name or None), seen a day apart."""
        c = ScopeCandidate(
            root_entity_id=root.id, kind="domain", value=target.value, status="claimed",
            affiliated_entity_id=root.id, decided_at=T0, decided_by_id=self.admin.id,
            accepted_into="estate", target_id=target.id)
        self.db.add(c)
        self.db.flush()
        for i, (signal_type, observer) in enumerate(signals):
            ev = self.w.evidence_row()
            observer_id = (
                self.db.query(Observer.id).filter(Observer.name == observer).scalar() if observer else None)
            self.db.add(ScopeSignal(
                candidate_id=c.id, signal_type=signal_type, anchor_kind="person", anchor_user_id=self.admin.id,
                via_entity_id=root.id, evidence_id=ev.id, quote=f"{_QUOTE_MARKER} {i}",
                matched_values=[f"{_MATCH_MARKER}-{i}"], observer_id=observer_id,
                first_seen_at=T0 + timedelta(days=i), last_seen_at=T1 + timedelta(days=i)))
        self.db.commit()
        return c

    # -- reading ---------------------------------------------------------------

    def build(self, asset: AssetCanonical):
        self.db.expire_all()
        return build_attribution(self.db, self.admin, asset)

    def cleanup(self) -> None:
        try:
            self.db.rollback()
            self.xw.cleanup()
        finally:
            try:
                for oid in self.observer_ids:
                    cleanup_observer(self.w.db, oid)
            finally:
                self.w.close()


@pytest.fixture
def env():
    e = _Env()
    try:
        yield e
    finally:
        e.cleanup()


def _kinds(chain) -> list[str]:
    return [h.kind for h in chain.hops]


def _claimed_world(env, *, proven: bool = False):
    """ours root -> domain target (claimed candidate: one strong, one
    supporting signal) -> hostname and address both linked to it; the address
    carries a sighting and an affinity claim (and a cloud inventory when
    `proven`). Returns (root, target, host asset, address asset)."""
    ip, host = _a(0), _host()
    env.assets(addresses=[ip], records=[(host, "A", ip)])
    root = env.w.ours()
    target = env.target(_DOM, entity=root)
    env.claimed_candidate(root, target, [("filer_10k_website", None), ("shared_vanity_ns", "cert_transparency")])
    host_asset, ip_asset = env.asset(host), env.asset(ip)
    env.link(target, host_asset)
    env.link(target, ip_asset)
    env.claim(ip_asset, "dns_resolve", "observation")
    env.claim(ip_asset, "shared_infra_verifier", "affinity_confirmation", {"verdict": "confirmed_ours"})
    if proven:
        env.claim(ip_asset, env.throwaway_observer(), "cloud_inventory", {"confirmed": True})
    env.project(ip_asset)
    return root, target, host_asset, ip_asset


# 1 ------------------------------------------------------------------------


def test_claimed_asset_has_one_full_chain_and_claimed_ownership(env):
    root, target, host_asset, ip_asset = _claimed_world(env)
    att = env.build(ip_asset)

    assert att.chains_truncated is False
    (chain,) = att.chains
    assert chain.target_id == target.id
    assert _kinds(chain) == ["organization", "scope", "host", "address"]
    org, scope, host, addr = chain.hops

    assert (org.status, org.entity_id, org.name, org.relationship) == ("observed", root.id, root.legal_name, "ours")
    assert org.marked_by_id == root.ours_authorised_by_id and org.marked_at == root.ours_authorised_at
    assert org.evidence == [] and org.tier is None

    assert (scope.status, scope.target_id, scope.target_type, scope.value) == ("observed", target.id, "domain", _DOM)
    assert scope.reason is None and scope.tier == "strong" and scope.evidence_truncated is False
    assert scope.candidate_id is not None and scope.claimed_at == T0 and scope.claimed_by_id == env.admin.id
    assert [(e.signal_type, e.tier, e.source) for e in scope.evidence] == [
        ("filer_10k_website", "strong", None), ("shared_vanity_ns", "supporting", "cert_transparency")]
    assert [e.label for e in scope.evidence] == [
        tiers.SIGNALS["filer_10k_website"].label, tiers.SIGNALS["shared_vanity_ns"].label]
    assert all(e.kind == "signal" and e.evidence_id is not None for e in scope.evidence)

    assert (host.status, host.reason) == ("derived", _DERIVED_NAMES_ABOVE_ADDRESS)
    assert [c.value for c in host.candidates] == [_host()] and host.candidates_truncated is False
    assert host.evidence == [] and host.tier is None

    assert (addr.status, addr.address, addr.asset_id, addr.reason) == ("observed", _a(0), ip_asset.id, None)
    assert (addr.first_seen_at, addr.last_seen_at) == (T0, T1)
    assert [(e.claim_type, e.source, e.source_trust, e.tier) for e in addr.evidence] == [
        ("observation", "dns_resolve", "observed", "strong")]
    assert addr.tier == "strong"

    own = att.ownership
    assert (own.surface, own.reason, own.tier) == ("claimed_ours", _CLAIMED, "supporting")
    assert [(e.claim_type, e.source, e.outcome, e.tier) for e in own.evidence] == [
        ("affinity_confirmation", "shared_infra_verifier", "confirmed_ours", "supporting")]


# 2 ------------------------------------------------------------------------


def test_proven_asset_has_strong_ownership_and_no_reason(env):
    _, _, _, ip_asset = _claimed_world(env, proven=True)
    own = env.build(ip_asset).ownership
    assert own.surface == "proven_ours"
    assert own.reason is None
    assert own.tier == "strong"
    assert [(e.claim_type, e.outcome, e.tier) for e in own.evidence] == [
        ("affinity_confirmation", "confirmed_ours", "supporting"), ("cloud_inventory", "confirmed", "strong")]


# 3 ------------------------------------------------------------------------


def test_an_asset_under_no_target_has_one_unknown_chain(env):
    ip = _a(0)
    env.assets(addresses=[ip])
    att = env.build(env.asset(ip))
    (chain,) = att.chains
    assert chain.target_id is None and _kinds(chain) == ["organization", "scope", "address"]
    org, scope, addr = chain.hops
    assert (org.status, org.reason) == ("unknown", _NO_TARGET_ORG)
    assert (scope.status, scope.reason, scope.target_id, scope.tier) == ("unknown", _NO_TARGET, None, None)
    assert (addr.status, addr.reason, addr.address) == ("unknown", _NO_TARGET, ip)
    assert att.ownership.surface == "unknown"
    assert att.ownership.reason == _NO_OWNERSHIP_CHECK
    assert att.ownership.tier is None and att.ownership.evidence == []


# 4 ------------------------------------------------------------------------


def test_no_tier_without_an_evidence_row(env):
    host = _host()
    env.assets(records=[(host, "A", _a(0))], addresses=[_a(0)])
    root = env.w.ours()
    target = env.target(_DOM, entity=root)
    asset = env.asset(host)
    env.link(target, asset)
    # Reached: the claims were deleted by `assets`, and the target has an entity but no candidate.
    assert env.db.query(AssetClaim).filter(AssetClaim.asset_canonical_id == asset.id).count() == 0
    assert env.db.query(ScopeCandidate).filter(ScopeCandidate.target_id == target.id).count() == 0

    (chain,) = env.build(asset).chains
    org, scope, hop = chain.hops
    assert org.status == "observed"
    assert scope.status == "observed" and scope.reason == _SCOPE_NO_CANDIDATE
    assert scope.evidence == [] and scope.tier is None and scope.candidate_id is None
    assert hop.status == "observed"
    assert hop.evidence == [] and hop.tier is None


# 5 ------------------------------------------------------------------------


def test_a_target_with_no_entity_has_an_unknown_organization(env):
    host = _host()
    env.assets(records=[(host, "A", _a(0))], addresses=[_a(0)])
    target = env.target(_DOM)
    asset = env.asset(host)
    env.link(target, asset)
    (chain,) = env.build(asset).chains
    assert _kinds(chain) == ["organization", "scope", "host"]
    org, scope, _ = chain.hops
    assert (org.status, org.reason, org.entity_id) == ("unknown", _NO_ORG_ON_TARGET, None)
    assert (scope.status, scope.reason, scope.tier, scope.evidence) == ("observed", None, None, [])


# 6 ------------------------------------------------------------------------


def _entity_world(env, *, confirm_acquired: bool = True):
    """ours root --acquired--> A, and B subsidiary_of A; a target on B with
    the hostname linked to it. Returns (root, A, B, asset)."""
    host = _host()
    env.assets(records=[(host, "A", _a(0))], addresses=[_a(0)])
    root = env.w.ours()
    a = env.w.entity()
    env.w.edge(root, a, "acquired", confirm=confirm_acquired)
    b = env.w.child_of(a)
    target = env.target(_DOM, entity=b)
    asset = env.asset(host)
    env.link(target, asset)
    return root, a, b, asset


def test_entity_hops_run_from_the_organization_down_to_the_targets_entity(env):
    root, a, b, asset = _entity_world(env)
    (chain,) = env.build(asset).chains
    assert _kinds(chain) == ["organization", "entity", "entity", "scope", "host"]
    org, ent_a, ent_b = chain.hops[:3]
    assert (org.status, org.entity_id, org.relationship) == ("observed", root.id, "ours")
    assert (ent_a.entity_id, ent_a.name, ent_a.relation, ent_a.status) == (a.id, a.legal_name, "acquired", "observed")
    assert ent_a.tier == "strong" and len(ent_a.evidence) == 1
    ev = ent_a.evidence[0]
    assert (ev.kind, ev.relation, ev.tier, ev.confirmed_by) == ("relation", "acquired", "strong", "person")
    assert ev.source is not None and ev.evidence_id is not None and ev.confirmed_at is not None
    assert ev.event_date is None and ev.event_date_precision == "unknown"
    assert (ent_b.entity_id, ent_b.relation, ent_b.tier) == (b.id, "subsidiary_of", "strong")
    assert ent_a.first_seen_at is None and ent_a.last_seen_at is None


def test_a_proposed_relation_is_not_walked(env):
    _, a, b, asset = _entity_world(env, confirm_acquired=False)
    (chain,) = env.build(asset).chains
    # Reached: the proposed row exists and the confirmed B -> A one is walked.
    proposed = env.db.query(EntityRelation).filter(
        EntityRelation.relation == "acquired", EntityRelation.object_id == a.id).one()
    assert proposed.status == "proposed"
    assert _kinds(chain) == ["organization", "entity", "entity", "scope", "host"]
    org, top, below = chain.hops[:3]
    assert (org.status, org.reason, org.entity_id) == ("unknown", _NO_ORG_ABOVE_ENTITY, None)
    # The top entity has no confirmed relation leading up from it.
    assert (top.entity_id, top.relation, top.evidence, top.tier) == (a.id, None, [], None)
    assert (below.entity_id, below.relation, below.tier) == (b.id, "subsidiary_of", "strong")


# 7 ------------------------------------------------------------------------


def test_two_sources_for_one_relation_are_two_evidence_rows(env):
    root, a, b, asset = _entity_world(env)
    second = make_observer(env.w.db, name=f"ac358-{uuid.uuid4().hex[:8]}")
    env.w.observers.append(second.id)
    ev = make_evidence(env.w.db, content=f"ac358 {uuid.uuid4().hex}".encode(), source_url="https://example.test/ac")
    env.w.evidence.append(ev.id)
    rel = entity_graph.assert_relation(
        env.w.db, subject_id=root.id, object_id=a.id, relation="acquired",
        observer_id=second.id, evidence_id=ev.id, quote="ac358", event_date=None, event_date_precision="unknown")
    env.w.relations.append(rel.id)
    entity_graph.decide(env.w.db, relation_id=rel.id, status="confirmed", user=env.admin)
    first_observer = env.w.db.get(Observer, env.w.observers[0]).name

    (chain,) = env.build(asset).chains
    ent_a = chain.hops[1]
    assert ent_a.entity_id == a.id and ent_a.relation == "acquired"
    assert len(ent_a.evidence) == 2
    assert {e.source for e in ent_a.evidence} == {first_observer, second.name}
    assert len({e.relation_id for e in ent_a.evidence}) == 2


# 8 ------------------------------------------------------------------------


def test_two_parents_give_two_chains_neither_promoted(env):
    host = _host()
    env.assets(records=[(host, "A", _a(0))], addresses=[_a(0)])
    root1, root2 = env.w.ours(), env.w.ours()
    p1, p2 = env.w.child_of(root1), env.w.child_of(root2)
    b = env.w.child_of(p1)
    env.w.edge(b, p2, "subsidiary_of")
    target = env.target(_DOM, entity=b)
    asset = env.asset(host)
    env.link(target, asset)

    att = env.build(asset)
    assert len(att.chains) == 2 and att.chains_truncated is False
    expected = [(p.id, r.id) for p, r in sorted([(p1, root1), (p2, root2)], key=lambda pr: pr[0].id)]
    got = [(c.hops[1].entity_id, c.hops[0].entity_id) for c in att.chains]
    assert got == expected
    for chain in att.chains:
        assert _kinds(chain) == ["organization", "entity", "entity", "scope", "host"]
        assert chain.hops[0].status == "observed" and chain.hops[2].entity_id == b.id
        assert chain.target_id == target.id
    # Stable: a second build gives the same order.
    assert [(c.hops[1].entity_id, c.hops[0].entity_id) for c in env.build(asset).chains] == expected


# 9 ------------------------------------------------------------------------


def test_the_walk_stops_at_the_nearest_marked_entity(env):
    host = _host()
    env.assets(records=[(host, "A", _a(0))], addresses=[_a(0)])
    root = env.w.ours()
    x = env.w.child_of(root)
    x, _eng = env.w.deal(x)
    b = env.w.child_of(x)
    target = env.target(_DOM, entity=b)
    asset = env.asset(host)
    env.link(target, asset)
    assert x.relationship == "ma_target" and root.relationship == "ours"  # both marked: the walk could pass x

    (chain,) = env.build(asset).chains
    assert _kinds(chain) == ["organization", "entity", "scope", "host"]
    org, ent_b = chain.hops[:2]
    assert (org.entity_id, org.relationship, org.marked_at, org.marked_by_id) == (x.id, "ma_target", None, None)
    assert ent_b.entity_id == b.id and ent_b.relation == "subsidiary_of"
    assert root.id not in {getattr(h, "entity_id", None) for h in chain.hops}


# 10 -----------------------------------------------------------------------


def test_two_targets_covering_one_asset_are_two_chains_in_target_order(env):
    host = _host("www.sub")
    env.assets(records=[(host, "A", _a(0))], addresses=[_a(0)])
    root_a, root_b = env.w.ours(), env.w.ours()
    # Created second but first in time: target order is by `created_at`.
    t_late = env.target(_DOM, entity=root_a, created=T1)
    t_early = env.target(f"sub.{_DOM}", entity=root_b, created=T0)
    asset = env.asset(host)

    att = env.build(asset)
    assert [c.target_id for c in att.chains] == [t_early.id, t_late.id]
    assert [c.hops[0].entity_id for c in att.chains] == [root_b.id, root_a.id]
    for chain in att.chains:
        assert _kinds(chain) == ["organization", "scope", "host"]
        assert (chain.hops[2].status, chain.hops[2].reason) == ("derived", _DERIVED_BY_NAME)


# 11 -----------------------------------------------------------------------


def test_a_third_party_name_reached_by_cname_is_not_ours(env):
    ip, front, back = _a(0), _host("front"), f"tp-{uuid.uuid4().hex[:8]}.example.net"
    env.assets(addresses=[ip], records=[(front, "CNAME", back), (back, "A", ip)])
    root = env.w.ours()
    target = env.target(_DOM, entity=root)
    front_asset, back_asset = env.asset(front), env.asset(back)
    env.link(target, back_asset)  # the boundary node is recorded under the target by discovery
    # The claim is inserted directly: the boundary classification belongs to the scan pipeline.
    env.claim(back_asset, "dns_resolve", "third_party_dependency", {"relationship": "cdn"})
    env.claim(back_asset, "dns_resolve", "observation")
    env.project(back_asset)
    assert front_asset.value.endswith(_DOM) and not back.endswith(_DOM)

    att = env.build(back_asset)
    (chain,) = att.chains
    assert _kinds(chain) == ["organization", "scope", "host", "host"]
    middle, own = chain.hops[2], chain.hops[3]
    assert (middle.status, middle.reason) == ("derived", _DERIVED_NAMES_ABOVE_HOST)
    assert [(c.asset_id, c.value, c.distance) for c in middle.candidates] == [(front_asset.id, front, 1)]
    assert middle.evidence == [] and middle.tier is None
    assert (own.status, own.hostname, own.asset_id) == ("observed", back, back_asset.id)
    own_ = att.ownership
    assert (own_.surface, own_.reason, own_.tier) == ("not_ours", _NOT_OURS_THIRD_PARTY, None)
    assert [(e.claim_type, e.outcome, e.tier) for e in own_.evidence] == [
        ("third_party_dependency", "third_party_dependency", None)]


# 12 -----------------------------------------------------------------------


def test_unknown_ownership_with_a_complete_chain(env):
    host = _host()
    env.assets(records=[(host, "A", _a(0))], addresses=[_a(0)])
    root = env.w.ours()
    target = env.target(_DOM, entity=root)
    asset = env.asset(host)
    env.link(target, asset)
    env.claim(asset, "dns_resolve", "observation")
    env.project(asset)
    assert env.db.query(AssetState).filter(AssetState.asset_canonical_id == asset.id).one().estate is None

    att = env.build(asset)
    assert (att.ownership.surface, att.ownership.reason, att.ownership.tier) == ("unknown", _NO_OWNERSHIP_CHECK, None)
    (chain,) = att.chains
    assert _kinds(chain) == ["organization", "scope", "host"]
    assert [h.status for h in chain.hops] == ["observed", "observed", "observed"]


# 13 -----------------------------------------------------------------------


@pytest.mark.parametrize("trust, expected", [
    ("observed", "strong"), ("derived", "supporting"), ("inferred", "context"), (None, None), ("bogus", None)])
def test_observation_tier_follows_the_observers_trust(trust, expected):
    assert attribution_tiers.sighting_tier("observation", trust) == expected


@pytest.mark.parametrize("trust", ["observed", "derived", "inferred", None])
def test_ct_issuance_is_strong_whatever_the_trust(trust):
    assert attribution_tiers.sighting_tier("ct_cert_issuance", trust) == "strong"


def test_other_claim_types_are_no_sighting():
    assert attribution_tiers.sighting_tier("port_observation", "observed") is None
    assert attribution_tiers.sighting_tier("not_a_claim_type", "observed") is None


@pytest.mark.parametrize("claim_type, value, expected", [
    ("cloud_inventory", {"confirmed": True}, "strong"),
    ("cloud_inventory", {"confirmed": False}, None),
    ("cloud_inventory", {"confirmed": "yes"}, None),
    ("cloud_inventory", {}, None),
    ("affinity_confirmation", {"verdict": "confirmed_ours"}, "supporting"),
    ("affinity_confirmation", {"verdict": "unverified"}, None),
    ("affinity_confirmation", {"verdict": "rejected_shared_infra"}, None),
    ("tenancy", {"tenancy": "single_tenant"}, "context"),
    ("tenancy", {"tenancy": "not_single_tenant"}, None),
    ("tenancy", {"tenancy": "undetermined"}, None),
    ("third_party_dependency", {"relationship": "cdn"}, None),
    ("observation", {}, None),
    ("cloud_inventory", None, None),
])
def test_ownership_tier_table(claim_type, value, expected):
    assert attribution_tiers.ownership_tier(claim_type, value) == expected


def test_highest_orders_strong_over_supporting_over_context():
    h = attribution_tiers.highest
    assert h(["context", "supporting", "strong"]) == "strong"
    assert h(["context", None, "supporting"]) == "supporting"
    assert h(["context"]) == "context"
    assert h([None, None]) is None
    assert h([]) is None


def test_signal_tier_follows_the_candidate_table():
    assert attribution_tiers.signal_tier("filer_10k_website") == "strong"
    assert attribution_tiers.signal_tier("shared_vanity_ns") == "supporting"
    assert attribution_tiers.signal_tier("not_a_signal") is None


def test_every_observer_trust_has_a_tier():
    assert set(attribution_tiers.OBSERVER_TRUST_TIERS) == set(OBSERVER_TRUST)


# 14 -----------------------------------------------------------------------


def _sighted_host(env):
    host = _host()
    env.assets(records=[(host, "A", _a(0))], addresses=[_a(0)])
    root = env.w.ours()
    target = env.target(_DOM, entity=root)
    asset = env.asset(host)
    env.link(target, asset)
    env.claim(asset, "shodan", "observation", at=T0)  # inferred observer
    env.claim(asset, "dns_resolve", "observation", at=T1)  # observed observer
    return asset


def test_sighting_rows_carry_the_observers_trust_tier(env):
    asset = _sighted_host(env)
    hop = env.build(asset).chains[0].hops[-1]
    assert [(e.source, e.source_trust, e.tier, e.outcome) for e in hop.evidence] == [
        ("shodan", "inferred", "context", None), ("dns_resolve", "observed", "strong", None)]
    assert hop.tier == "strong"

    env.db.query(AssetClaim).filter(
        AssetClaim.asset_canonical_id == asset.id,
        AssetClaim.observer_id == env.db.query(Observer.id).filter(Observer.name == "dns_resolve").scalar_subquery(),
    ).delete(synchronize_session=False)
    env.db.commit()
    hop = env.build(asset).chains[0].hops[-1]
    assert [e.source for e in hop.evidence] == ["shodan"]
    assert hop.tier == "context"


# 15 -----------------------------------------------------------------------


def test_evidence_is_capped_but_the_tier_is_taken_over_every_row(env, monkeypatch):
    asset = _sighted_host(env)
    monkeypatch.setattr(attribution_chain, "MAX_EVIDENCE_ROWS", 1)
    hop = env.build(asset).chains[0].hops[-1]
    assert [e.source for e in hop.evidence] == ["shodan"]  # the strong row is second, so not listed
    assert hop.evidence_truncated is True
    assert hop.tier == "strong"


# 16 -----------------------------------------------------------------------


def test_chains_are_capped(env, monkeypatch):
    host = _host("www.sub")
    env.assets(records=[(host, "A", _a(0))], addresses=[_a(0)])
    env.target(_DOM, entity=env.w.ours(), created=T0)
    env.target(f"sub.{_DOM}", entity=env.w.ours(), created=T1)
    asset = env.asset(host)
    assert len(env.build(asset).chains) == 2  # reached: two chains exist before the cap
    monkeypatch.setattr(attribution_chain, "MAX_CHAINS", 1)
    att = env.build(asset)
    assert len(att.chains) == 1 and att.chains_truncated is True


# 17 -----------------------------------------------------------------------


def test_an_address_under_an_ip_target_is_derived_by_range(env):
    ip = _a(0)
    env.assets(addresses=[ip])
    root = env.w.ours()
    target = env.target(ip, ttype="ip", entity=root)
    (chain,) = env.build(env.asset(ip)).chains
    assert chain.target_id == target.id
    assert _kinds(chain) == ["organization", "scope", "address"]
    scope, addr = chain.hops[1:]
    assert (scope.target_type, scope.value) == ("ip", ip)
    assert (addr.status, addr.reason, addr.address) == ("derived", _DERIVED_BY_RANGE, ip)


# 18 -----------------------------------------------------------------------


def test_a_signals_quote_and_matched_values_never_appear(env):
    _, _, _, ip_asset = _claimed_world(env)
    # Reached: the markers are stored and the signals are listed.
    assert env.db.query(ScopeSignal).filter(ScopeSignal.quote.like(f"{_QUOTE_MARKER}%")).count() == 2
    assert env.db.query(ScopeSignal).filter(ScopeSignal.matched_values.any(f"{_MATCH_MARKER}-0")).count() == 1
    att = env.build(ip_asset)
    assert len(att.chains[0].hops[1].evidence) == 2
    dumped = att.model_dump_json()
    assert "MARKER" not in dumped


# derived-by-parent, and no name above the address ----------------------------


def test_an_address_under_a_domain_by_its_parent_has_no_name_above_it(env):
    ip, host = _a(0), _host()
    env.assets(addresses=[ip])
    root = env.w.ours()
    env.target(_DOM, entity=root)
    asset = env.asset(ip)
    env.db.query(AssetCanonical).filter(AssetCanonical.id == asset.id).update({"parent_value": host})
    env.db.commit()
    (chain,) = env.build(asset).chains
    assert _kinds(chain) == ["organization", "scope", "host", "address"]
    middle, addr = chain.hops[2:]
    assert (middle.status, middle.candidates) == ("unknown", [])
    assert middle.reason == attribution_chain._NO_NAME_ABOVE_ADDRESS
    assert (addr.status, addr.reason) == ("derived", _DERIVED_BY_PARENT)


# cycle, depth cap, and the DNS walk's `keep` -----------------------------------


def test_a_cycle_in_the_organization_graph_ends_and_lists_each_entity_once(env):
    host = _host()
    env.assets(records=[(host, "A", _a(0))], addresses=[_a(0)])
    a, b = env.w.entity(), env.w.entity()
    env.w.edge(a, b, "subsidiary_of")
    env.w.edge(b, a, "subsidiary_of")
    target = env.target(_DOM, entity=a)
    asset = env.asset(host)
    env.link(target, asset)
    # Reached: both rows are confirmed, so each entity does have a parent.
    assert env.db.query(EntityRelation).filter(
        EntityRelation.status == "confirmed", EntityRelation.relation == "subsidiary_of",
        EntityRelation.subject_id.in_([a.id, b.id])).count() == 2

    out: list = []

    def run():
        try:
            out.append(env.build(asset))
        except BaseException as e:  # reported by the assertion below
            out.append(e)

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(timeout=10)
    assert not t.is_alive(), "the build did not return"
    (att,) = out
    assert not isinstance(att, BaseException), att
    assert att.chains
    for chain in att.chains:
        entity_ids = [h.entity_id for h in chain.hops if h.kind == "entity"]
        assert sorted(entity_ids) == sorted([a.id, b.id])
        org = chain.hops[0]
        assert (org.status, org.reason) == ("unknown", _NO_ORG_ABOVE_ENTITY)


def test_the_depth_cap_stops_the_walk_up_the_organization_graph(env, monkeypatch):
    root, a, b, asset = _entity_world(env)
    (chain,) = env.build(asset).chains
    assert chain.hops[0].entity_id == root.id  # the real cap reaches the root

    monkeypatch.setattr(attribution_chain, "MAX_DEPTH", 1)
    (chain,) = env.build(asset).chains
    org = chain.hops[0]
    assert (org.status, org.reason) == ("unknown", _NO_ORG_ABOVE_ENTITY)
    assert [h.entity_id for h in chain.hops if h.kind == "entity"] == [a.id, b.id]
    assert root.id not in {getattr(h, "entity_id", None) for h in chain.hops}


_OTHER = f"{_LABEL}.example.net"


def _address_world(env, records):
    """An address linked to a domain target, pointed at by `records`."""
    ip = _a(0)
    env.assets(addresses=[ip], records=records)
    target = env.target(_DOM, entity=env.w.ours())
    asset = env.asset(ip)
    env.link(target, asset)
    return asset


def _host_hop(env, asset):
    (chain,) = env.build(asset).chains
    return [h for h in chain.hops if h.kind == "host"][0]


def _unfiltered(env, asset, **kw):
    return dns_walk.walk(env.db, lambda entity: true(), [asset.id], upward=True, **kw)


def test_keep_does_not_stop_the_walk(env):
    via, www = f"via.{_OTHER}", _host("www")
    asset = _address_world(env, [(via, "A", _a(0)), (www, "CNAME", via)])
    # Reached: the name turned down sits between the address and the wanted name.
    names, _ = _unfiltered(env, asset)
    assert [(c.value, c.distance) for c in names] == [(via, 1), (www, 2)]

    hop = _host_hop(env, asset)
    assert hop.status == "derived"
    assert [(c.value, c.distance) for c in hop.candidates] == [(www, 2)]


def test_names_turned_down_do_not_crowd_out_the_targets(env, monkeypatch):
    other, mine = f"aaa.{_OTHER}", _host("zzz")
    asset = _address_world(env, [(other, "A", _a(0)), (mine, "A", _a(0))])
    monkeypatch.setattr(dns_walk, "MAX_CANDIDATES", 1)
    # Reached: unfiltered, the cap keeps the name that sorts first, which is not the target's.
    names, truncated = _unfiltered(env, asset)
    assert [c.value for c in names] == [other] and truncated is True

    hop = _host_hop(env, asset)
    assert [c.value for c in hop.candidates] == [mine]
    assert hop.candidates_truncated is False


def test_a_walk_cut_short_says_so_instead_of_none_on_file(env, monkeypatch):
    asset = _address_world(env, [(f"one.{_OTHER}", "A", _a(0)), (f"two.{_OTHER}", "A", _a(0))])
    # Reached: two names point at the address, neither under the target.
    names, _ = _unfiltered(env, asset)
    assert len(names) == 2

    hop = _host_hop(env, asset)
    assert (hop.status, hop.reason, hop.candidates) == ("unknown", _NO_NAME_ABOVE_ADDRESS, [])

    monkeypatch.setattr(dns_walk, "_LEVEL_ROW_LIMIT", 1)
    hop = _host_hop(env, asset)
    assert (hop.status, hop.reason, hop.candidates) == ("unknown", _WALK_CUT_SHORT, [])


# two claimed candidates, and a certificate-log sighting ---------------------------


def test_the_earlier_claimed_candidate_is_the_one_reported(env):
    host = _host()
    env.assets(records=[(host, "A", _a(0))], addresses=[_a(0)])
    r1, r2 = env.w.ours(), env.w.ours()
    target = env.target(_DOM, entity=r1)
    late = env.claimed_candidate(r1, target, [("filer_10k_website", None)])
    env.db.query(ScopeCandidate).filter(ScopeCandidate.id == late.id).update({"decided_at": T2})
    env.db.commit()
    early = env.claimed_candidate(r2, target, [("shared_vanity_ns", "cert_transparency")])  # decided at T0
    asset = env.asset(host)
    env.link(target, asset)
    assert env.db.query(ScopeCandidate).filter(
        ScopeCandidate.target_id == target.id, ScopeCandidate.status == "claimed").count() == 2

    (chain,) = env.build(asset).chains
    scope = chain.hops[1]
    assert scope.candidate_id == early.id and scope.claimed_at == T0
    assert [e.signal_type for e in scope.evidence] == ["shared_vanity_ns"]


def test_a_certificate_log_issuance_is_strong_evidence_on_the_hostname(env):
    host, ip = _host(), _a(0)
    env.assets(records=[(host, "A", ip)], addresses=[ip])
    target = env.target(_DOM, entity=env.w.ours())
    asset = env.asset(host)
    env.link(target, asset)
    # The producer's own path: metadata through `emit_claims`.
    emit = DiscoveredAsset(
        asset_type="dns_record", value=host, parent_value=None, observer="cert_transparency",
        asset_metadata={"record_type": "A", "content": ip, "not_before": "2020-01-01", "not_after": "2021-01-01",
                        "issuer": "Example CA"})
    claim_emitter.emit_claims(env.db, [emit], {("dns_record", host, "A", ip): asset.id}, T0)
    env.db.commit()
    assert env.db.query(AssetClaim).filter(
        AssetClaim.asset_canonical_id == asset.id, AssetClaim.claim_type == "ct_cert_issuance").count() == 1

    hop = env.build(asset).chains[0].hops[-1]
    assert hop.kind == "host" and hop.asset_id == asset.id
    ct = [e for e in hop.evidence if e.claim_type == "ct_cert_issuance"]
    assert len(ct) == 1 and ct[0].tier == "strong" and ct[0].source == "cert_transparency"
    assert hop.tier == "strong"


# ownership tier, scope tier over every signal, the `_under` boundary ----------------


def test_a_not_ours_asset_has_no_ownership_tier_though_a_row_has_one(env):
    ip = _a(0)
    env.assets(addresses=[ip])
    asset = env.asset(ip)
    env.claim(asset, "shared_infra_verifier", "affinity_confirmation", {"verdict": "rejected_shared_infra"})
    env.claim(asset, "tenancy_enricher", "tenancy", {"tenancy": "single_tenant"})
    env.project(asset)

    own = env.build(asset).ownership
    # Reached: a row has a tier, so a tier taken over the rows would not be None.
    assert attribution_tiers.highest(e.tier for e in own.evidence) is not None
    assert [(e.claim_type, e.tier) for e in own.evidence if e.claim_type == "tenancy"] == [("tenancy", "context")]
    assert own.surface == "not_ours"
    assert own.tier is None


def test_the_scope_tier_is_taken_over_signals_not_listed(env, monkeypatch):
    host = _host()
    env.assets(records=[(host, "A", _a(0))], addresses=[_a(0)])
    root = env.w.ours()
    target = env.target(_DOM, entity=root)
    # Earliest first: supporting, then strong.
    env.claimed_candidate(root, target, [("shared_vanity_ns", "cert_transparency"), ("filer_10k_website", None)])
    asset = env.asset(host)
    env.link(target, asset)
    monkeypatch.setattr(attribution_chain, "MAX_EVIDENCE_ROWS", 1)

    scope = env.build(asset).chains[0].hops[1]
    assert [e.signal_type for e in scope.evidence] == ["shared_vanity_ns"]
    assert [e.tier for e in scope.evidence] == ["supporting"]
    assert scope.evidence_truncated is True
    assert scope.tier == "strong"


def test_under_needs_a_dot_boundary():
    under = attribution_chain._under
    dom = "acme.example.org"
    assert under("acme.example.org", dom)
    assert under("www.acme.example.org", dom)
    assert under("WWW.Acme.Example.Org.", dom)
    assert under("acme.example.org", "ACME.example.org.")
    assert not under("notacme.example.org", dom)
    assert not under("example.org", dom)


def test_a_name_that_only_ends_with_the_domain_text_is_not_under_it(env):
    near = f"x{_DOM}"
    asset = _address_world(env, [(_host("www"), "A", _a(0)), (near, "A", _a(0))])
    # Reached: both names are readable and point at the address.
    names, _ = _unfiltered(env, asset)
    assert sorted(c.value for c in names) == sorted([_host("www"), near])

    hop = _host_hop(env, asset)
    assert [c.value for c in hop.candidates] == [_host("www")]
