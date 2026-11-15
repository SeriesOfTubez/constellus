"""Read scope on the attribution chain (planning#358), at the service level.

The rule under test: **a row the reader may not read and a row that does not
exist produce the same response, byte for byte.** Every test therefore has the
same shape. Build the world. Read it with the row hidden (H). Show the path was
REACHED: the unhidden read (U) differs from H and contains the row's id, and H
does not. Then delete the hidden row(s) for real and read as an unrestricted
reader (D). Assert `H == D` on `model_dump(mode="json")`.

Rows are hidden by patching the `read_scope` clause the builder calls (today
the entity, relation and domain clauses grant everything), or by denying a
permission; the hostname test uses the REAL read scope, with a closed
engagement and a plain viewer.

Synthetic data only: `acs-<hex>.example.org` / `.example.net`, `Example
Holdings ...` entities, addresses `_a(0)` of test_exposure_path.py.

Run with:  backend/scripts/test.sh app/tests/test_attribution_chain_scope.py
"""

import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import or_

from app.models.asset_canonical import AssetCanonical
from app.models.asset_edge import AssetEdge
from app.models.asset_state import AssetState
from app.models.entity_relation import EntityRelation
from app.models.scope_candidate import ScopeCandidate, ScopeSignal
from app.models.target import Target
from app.models.target_asset_link import TargetAssetLink
from app.models.user import User
from app.services import attribution_chain, entity_graph, read_scope
from app.services.attribution_chain import (
    _NO_NAME_ABOVE_ADDRESS,
    _NO_ORG_ABOVE_ENTITY,
    _NO_ORG_ON_TARGET,
    _NO_TARGET_ORG,
    _SCOPE_NO_CANDIDATE,
    build_attribution,
)
from app.core.permissions import Permission
from app.tests._engagement import cleanup_engagement, make_engagement
from app.tests._entity_graph import make_evidence, make_observer
from app.tests.test_attribution_chain import T0, T1, _Env
from app.tests.test_exposure_path import _a, _purge

_LABEL = f"acs-{uuid.uuid4().hex[:8]}"
_DOM = f"{_LABEL}.example.org"
_CLOSED = f"{_LABEL}-closed.example.net"

_SIGNALS = [("filer_10k_website", None), ("shared_vanity_ns", "cert_transparency")]


class _ScopeEnv(_Env):
    """`_Env` plus cleanups for rows only this module makes, run first (the
    session closes with the base cleanup)."""

    def __init__(self):
        super().__init__()
        self.cleanups = []

    def cleanup(self):
        errors = []
        for fn in reversed(self.cleanups):
            try:
                self.db.rollback()
                fn()
            except Exception as e:  # keep cleaning; re-raised below
                errors.append(e)
        try:
            super().cleanup()
        finally:
            if errors:
                raise errors[0]


@pytest.fixture
def env():
    e = _ScopeEnv()
    try:
        yield e
    finally:
        e.cleanup()


# -- helpers -------------------------------------------------------------------


def _strings(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for v in node.values():
            yield from _strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from _strings(v)


def _dump(att) -> dict:
    return att.model_dump(mode="json")


def _hidden_vs_deleted(env, asset, *, patch, ids, delete, build=None):
    """U, then H (the `patch` applied), then D (after `delete()`), all read
    through `build` (default: the admin). Asserts the path was reached
    (`ids` are in U and not in H, and U != H) and that H == D."""
    build = build or env.build
    u = _dump(build(asset))
    with pytest.MonkeyPatch.context() as m:
        patch(m)
        h = _dump(build(asset))
    assert ids, "no ids to look for: the reached check would be empty"
    u_strings, h_strings = list(_strings(u)), list(_strings(h))
    for i in ids:
        assert str(i) in u_strings, "the row is not in the unhidden response"
        assert str(i) not in h_strings, "a hidden row reached the response"
    assert u != h
    delete()
    d = _dump(env.build(asset))
    assert h == d
    return u, h, d


def _full_world(env, dom):
    """ours root --acquired--> A; a domain target on A with a claimed candidate
    (two signals); hostnames www./api. under it pointing at one address, which
    is linked to the target and has a sighting. Returns a namespace."""
    ip, www, api = _a(0), f"www.{dom}", f"api.{dom}"
    env.assets(addresses=[ip], records=[(www, "A", ip), (api, "A", ip)])
    root = env.w.ours()
    a = env.w.entity()
    env.w.edge(root, a, "acquired")
    target = env.target(dom, entity=a)
    cand = env.claimed_candidate(root, target, _SIGNALS)
    ip_asset = env.asset(ip)
    env.link(target, ip_asset)
    env.claim(ip_asset, "dns_resolve", "observation")
    return SimpleNamespace(
        ip=ip, www=www, api=api, root=root, a=a, target=target, cand=cand, ip_asset=ip_asset)


def _delete_candidate(env, candidate_id):
    db = env.db
    db.rollback()
    db.query(ScopeSignal).filter(ScopeSignal.candidate_id == candidate_id).delete(synchronize_session=False)
    db.query(ScopeCandidate).filter(ScopeCandidate.id == candidate_id).delete(synchronize_session=False)
    db.commit()


def _delete_target(env, target_id):
    """The target, its links and its candidates (with their signals)."""
    db = env.db
    db.rollback()
    for (cid,) in db.query(ScopeCandidate.id).filter(ScopeCandidate.target_id == target_id).all():
        _delete_candidate(env, cid)
    db.query(TargetAssetLink).filter(TargetAssetLink.target_id == target_id).delete(synchronize_session=False)
    db.query(Target).filter(Target.id == target_id).delete(synchronize_session=False)
    db.commit()


def _null_entity(env, target_id):
    env.db.rollback()
    env.db.query(Target).filter(Target.id == target_id).update({"entity_id": None})
    env.db.commit()


def _delete_relations(env, ids):
    env.db.rollback()
    env.db.query(EntityRelation).filter(EntityRelation.id.in_(list(ids))).delete(synchronize_session=False)
    env.db.commit()


def _second_source(env, subject, obj, relation):
    """A second confirmed row for the same relation, from another observer."""
    second = make_observer(env.w.db, name=f"acs358-{uuid.uuid4().hex[:8]}")
    env.w.observers.append(second.id)
    ev = make_evidence(env.w.db, content=f"acs358 {uuid.uuid4().hex}".encode(), source_url="https://example.test/acs")
    env.w.evidence.append(ev.id)
    rel = entity_graph.assert_relation(
        env.w.db, subject_id=subject.id, object_id=obj.id, relation=relation,
        observer_id=second.id, evidence_id=ev.id, quote="acs358", event_date=None, event_date_precision="unknown")
    env.w.relations.append(rel.id)
    entity_graph.decide(env.w.db, relation_id=rel.id, status="confirmed", user=env.admin)
    return rel


def _hop(att, kind):
    return [h for h in att["chains"][0]["hops"] if h["kind"] == kind][0]


# 1 -- hidden target ---------------------------------------------------------


def test_a_hidden_target_reads_as_a_deleted_one(env):
    host = f"www.sub.{_DOM}"
    env.assets(records=[(host, "A", _a(0))], addresses=[_a(0)])
    root1, root2 = env.w.ours(), env.w.ours()
    t1 = env.target(_DOM, entity=root1, created=T0)
    t2 = env.target(f"sub.{_DOM}", entity=root2, created=T1)
    env.claimed_candidate(root1, t1, _SIGNALS)
    env.claimed_candidate(root2, t2, _SIGNALS)
    asset = env.asset(host)
    env.link(t1, asset)
    env.link(t2, asset)
    hidden, kept = t2.id, t1.id

    u, h, d = _hidden_vs_deleted(
        env, asset,
        patch=lambda m: m.setattr(read_scope, "target_clause", lambda user, target: target.id != hidden),
        ids=[hidden], delete=lambda: _delete_target(env, hidden))
    assert len(u["chains"]) == 2
    assert [c["target_id"] for c in h["chains"]] == [str(kept)]
    assert h["chains_truncated"] is False


# 2 -- hidden organization at the top -------------------------------------------


def test_a_hidden_organization_reads_as_no_relation_to_it(env):
    host = f"www.{_DOM}"
    env.assets(records=[(host, "A", _a(0))], addresses=[_a(0)])
    root = env.w.ours()
    a = env.w.entity()
    env.w.edge(root, a, "acquired")
    target = env.target(_DOM, entity=a)
    asset = env.asset(host)
    env.link(target, asset)
    root_id, a_id = root.id, a.id

    def delete():
        env.db.rollback()
        ids = [r for (r,) in env.db.query(EntityRelation.id).filter(
            or_(EntityRelation.subject_id == root_id, EntityRelation.object_id == root_id))]
        assert ids, "the relation rows to delete are not there"
        _delete_relations(env, ids)

    _, h, _ = _hidden_vs_deleted(
        env, asset,
        patch=lambda m: m.setattr(read_scope, "entity_clause", lambda user, entity: entity.id != root_id),
        ids=[root_id], delete=delete)
    (chain,) = h["chains"]
    assert [x["kind"] for x in chain["hops"]] == ["organization", "entity", "scope", "host"]
    org, ent = chain["hops"][:2]
    assert (org["status"], org["reason"], org["entity_id"]) == ("unknown", _NO_ORG_ABOVE_ENTITY, None)
    assert (ent["entity_id"], ent["relation"], ent["evidence"]) == (str(a_id), None, [])


# 3 -- hidden target entity -----------------------------------------------------


def _entity_target_world(env, *, candidate: bool):
    host = f"www.{_DOM}"
    env.assets(records=[(host, "A", _a(0))], addresses=[_a(0)])
    root = env.w.ours()
    a = env.w.entity()
    env.w.edge(root, a, "acquired")
    target = env.target(_DOM, entity=a)
    if candidate:
        env.claimed_candidate(root, target, _SIGNALS)
    asset = env.asset(host)
    env.link(target, asset)
    return a, target, asset


def test_a_hidden_target_entity_with_a_readable_candidate(env):
    a, target, asset = _entity_target_world(env, candidate=True)
    a_id, target_id = a.id, target.id
    u, h, d = _hidden_vs_deleted(
        env, asset,
        patch=lambda m: m.setattr(read_scope, "entity_clause", lambda user, entity: entity.id != a_id),
        ids=[a_id], delete=lambda: _null_entity(env, target_id))
    assert _hop(h, "organization")["reason"] == _NO_ORG_ON_TARGET
    # The candidate is readable in H and in D: the scope hop is the same in both.
    assert _hop(h, "scope") == _hop(d, "scope")
    assert _hop(h, "scope")["reason"] is None and len(_hop(h, "scope")["evidence"]) == 2
    assert _hop(u, "scope")["reason"] is None


def test_a_hidden_target_entity_with_no_candidate_adds_no_reason_to_the_scope(env):
    a, target, asset = _entity_target_world(env, candidate=False)
    a_id, target_id = a.id, target.id
    u, h, d = _hidden_vs_deleted(
        env, asset,
        patch=lambda m: m.setattr(read_scope, "entity_clause", lambda user, entity: entity.id != a_id),
        ids=[a_id], delete=lambda: _null_entity(env, target_id))
    # Reached: with the entity readable, the same scope hop says "no candidate on file".
    assert _hop(u, "scope")["reason"] == _SCOPE_NO_CANDIDATE
    assert _hop(h, "scope")["reason"] is None and _hop(d, "scope")["reason"] is None
    assert _hop(h, "organization")["reason"] == _NO_ORG_ON_TARGET


# 4 -- hidden relation ----------------------------------------------------------


def _relation_world(env):
    """ours root --acquired--> A (two sources), B subsidiary_of A, target on B."""
    host = f"www.{_DOM}"
    env.assets(records=[(host, "A", _a(0))], addresses=[_a(0)])
    root = env.w.ours()
    a = env.w.entity()
    env.w.edge(root, a, "acquired")
    b = env.w.child_of(a)
    first = env.db.query(EntityRelation).filter(
        EntityRelation.subject_id == root.id, EntityRelation.object_id == a.id).one()
    second = _second_source(env, root, a, "acquired")
    target = env.target(_DOM, entity=b)
    asset = env.asset(host)
    env.link(target, asset)
    return root, a, first.id, second.id, asset


def test_one_hidden_relation_reads_as_that_row_deleted(env):
    root, a, first_id, second_id, asset = _relation_world(env)
    u, h, d = _hidden_vs_deleted(
        env, asset,
        patch=lambda m: m.setattr(read_scope, "relation_clause", lambda user, rel: rel.id != second_id),
        ids=[second_id], delete=lambda: _delete_relations(env, [second_id]))
    top = [x for x in h["chains"][0]["hops"] if x["kind"] == "entity"][0]
    assert top["entity_id"] == str(a.id) and top["tier"] == "strong"
    assert [e["relation_id"] for e in top["evidence"]] == [str(first_id)]
    assert len([x for x in u["chains"][0]["hops"] if x["kind"] == "entity"][0]["evidence"]) == 2


def test_both_relation_rows_hidden_read_as_both_deleted(env):
    root, a, first_id, second_id, asset = _relation_world(env)
    both = [first_id, second_id]
    _, h, _ = _hidden_vs_deleted(
        env, asset,
        patch=lambda m: m.setattr(read_scope, "relation_clause", lambda user, rel: rel.id.notin_(both)),
        ids=both, delete=lambda: _delete_relations(env, both))
    org = _hop(h, "organization")
    assert (org["status"], org["reason"]) == ("unknown", _NO_ORG_ABOVE_ENTITY)


# 5 -- hidden candidate -----------------------------------------------------------


def test_a_hidden_candidate_reads_as_a_deleted_one(env):
    w = _full_world(env, _DOM)
    cand_id = w.cand.id
    signal_ids = [s for (s,) in env.db.query(ScopeSignal.id).filter(ScopeSignal.candidate_id == cand_id)]
    assert len(signal_ids) == 2
    _, h, _ = _hidden_vs_deleted(
        env, w.ip_asset,
        patch=lambda m: m.setattr(read_scope, "domain_clause", lambda user, cand: cand.id != cand_id),
        ids=[cand_id, *signal_ids], delete=lambda: _delete_candidate(env, cand_id))
    scope = _hop(h, "scope")
    assert scope["status"] == "observed" and scope["evidence"] == [] and scope["tier"] is None
    assert scope["reason"] == _SCOPE_NO_CANDIDATE and scope["candidate_id"] is None


# 6 -- hidden hostname, the real read scope ---------------------------------------


def test_a_hostname_the_viewer_may_not_read_reads_as_a_deleted_one(env):
    ip = _a(0)
    open_n, hid_n = f"open.{_DOM}", f"hid.{_DOM}"
    env.assets(addresses=[ip], records=[(open_n, "A", ip), (hid_n, "A", ip)])
    root = env.w.ours()
    ours = env.target(_DOM, entity=root)
    ip_asset, hid_asset = env.asset(ip), env.asset(hid_n)
    env.link(ours, ip_asset)

    # One closed engagement with one domain target; the hostname is linked to
    # it, so the viewer may not read the hostname though its name is under the
    # readable target's domain.
    engagement = make_engagement(env.db, "pre_close")
    closed = Target(id=uuid.uuid4(), type="domain", value=_CLOSED, engagement_id=engagement.id)
    env.db.add(closed)
    env.db.commit()
    closed_id, engagement_id = closed.id, engagement.id

    def drop_closed():
        env.db.query(TargetAssetLink).filter(TargetAssetLink.target_id == closed_id).delete(
            synchronize_session=False)
        env.db.query(Target).filter(Target.id == closed_id).delete(synchronize_session=False)
        env.db.commit()
        cleanup_engagement(env.db, engagement_id)

    env.cleanups.append(drop_closed)
    env.db.add(TargetAssetLink(
        target_id=closed_id, asset_canonical_id=hid_asset.id, first_linked_at=T0, last_observed_at=T1))
    env.db.commit()
    hid_id, ip_id = hid_asset.id, ip_asset.id

    viewer = env.db.get(User, env.w.user("viewer").id)
    admin = env.admin

    def readable(user, asset_id):
        return env.db.query(AssetCanonical.id).filter(
            AssetCanonical.id == asset_id, read_scope.asset_clause(user, AssetCanonical)).count() == 1

    # Reached: the address passes the viewer's read scope, the hostname does not, the admin reads both.
    assert readable(viewer, ip_id) and not readable(viewer, hid_id)
    assert readable(admin, ip_id) and readable(admin, hid_id)

    def build_viewer(asset):
        env.db.expire_all()
        return build_attribution(env.db, viewer, asset)

    def delete():
        env.db.rollback()
        env.db.query(TargetAssetLink).filter(TargetAssetLink.asset_canonical_id == hid_id).delete(
            synchronize_session=False)
        env.db.query(AssetState).filter(AssetState.asset_canonical_id == hid_id).delete(synchronize_session=False)
        env.db.commit()
        _purge(env.db, [hid_n])

    # U is the admin's read before the delete; H the viewer's; D the admin's after.
    u = _dump(env.build(ip_asset))
    h = _dump(build_viewer(ip_asset))

    def host_hop(body):
        return [x for x in body["chains"][0]["hops"] if x["kind"] == "host"][0]

    assert sorted(c["value"] for c in host_hop(u)["candidates"]) == sorted([open_n, hid_n])
    assert [c["value"] for c in host_hop(h)["candidates"]] == [open_n]
    assert str(hid_id) not in list(_strings(h)) and hid_n not in list(_strings(h))
    delete()
    d = _dump(env.build(ip_asset))
    assert [c["value"] for c in host_hop(d)["candidates"]] == [open_n]
    assert h == d


# 7 -- permission gates -------------------------------------------------------------


def _deny(m, permission):
    real = attribution_chain.has_permission
    m.setattr(attribution_chain, "has_permission", lambda user, p: False if p == permission else real(user, p))


def test_without_targets_read_every_covering_target_reads_as_deleted(env):
    w = _full_world(env, _DOM)
    target_id = w.target.id
    _, h, _ = _hidden_vs_deleted(
        env, w.ip_asset, patch=lambda m: _deny(m, Permission.TARGETS_READ),
        ids=[target_id], delete=lambda: _delete_target(env, target_id))
    (chain,) = h["chains"]
    assert chain["target_id"] is None
    assert chain["hops"][0]["reason"] == _NO_TARGET_ORG


def test_without_entities_read_entity_and_candidate_read_as_gone(env):
    w = _full_world(env, _DOM)
    target_id, cand_id = w.target.id, w.cand.id

    def delete():
        _null_entity(env, target_id)
        _delete_candidate(env, cand_id)

    _, h, _ = _hidden_vs_deleted(
        env, w.ip_asset, patch=lambda m: _deny(m, Permission.ENTITIES_READ),
        ids=[w.root.id, w.a.id, cand_id], delete=delete)
    assert _hop(h, "organization")["reason"] == _NO_ORG_ON_TARGET
    assert _hop(h, "scope")["reason"] is None and _hop(h, "scope")["candidate_id"] is None


def test_without_assets_read_the_candidate_hostnames_read_as_deleted(env):
    w = _full_world(env, _DOM)
    host_ids = [env.asset(w.www).id, env.asset(w.api).id]
    _, h, _ = _hidden_vs_deleted(
        env, w.ip_asset, patch=lambda m: _deny(m, Permission.ASSETS_READ),
        ids=host_ids, delete=lambda: _purge(env.db, [w.www, w.api]))
    host = _hop(h, "host")
    assert (host["status"], host["reason"], host["candidates"]) == ("unknown", _NO_NAME_ABOVE_ADDRESS, [])


# 8 -- every scoped read calls its clause ----------------------------------------------


def test_every_scoped_read_calls_its_clause(env, monkeypatch):
    w = _full_world(env, _DOM)
    names = ["target_clause", "entity_clause", "relation_clause", "domain_clause", "asset_clause"]
    calls = {n: 0 for n in names}

    def spy(name):
        original = getattr(read_scope, name)

        def wrapper(user, entity):
            calls[name] += 1
            return original(user, entity)

        monkeypatch.setattr(read_scope, name, wrapper)

    for n in names:
        spy(n)
    att = env.build(w.ip_asset)
    # Reached: the chain really has every kind of row the clauses guard.
    kinds = [h.kind for h in att.chains[0].hops]
    assert kinds == ["organization", "entity", "scope", "host", "address"]
    assert att.chains[0].hops[1].evidence and att.chains[0].hops[2].evidence
    assert [c.value for c in att.chains[0].hops[3].candidates] == [w.api, w.www]

    for n in names:
        assert calls[n] >= 1, f"{n} was never called"
    # The target's own entity, and the read of the parent above it.
    assert calls["entity_clause"] >= 2


# 9 -- the third-party name's own rows, the real read scope -----------------------


def test_a_hidden_record_row_of_a_third_party_name_is_not_a_start_of_the_walk(env):
    ip = _a(0)
    tp, www = f"tp.{_LABEL}.example.net", f"www.{_DOM}"
    # tp has an address row (the asset under test) and a TXT row (hidden below);
    # www has one TXT row, which makes no edge of its own.
    # Not `env.assets`: it reads one asset per name, and tp has two rows.
    env.xw.assets(addresses=[ip], records=[(tp, "A", ip), (tp, "TXT", "v9"), (www, "TXT", "t9")])
    root = env.w.ours()
    ours = env.target(_DOM, entity=root)
    env.db.expire_all()
    rows = {
        r.record_type: r for r in env.db.query(AssetCanonical).filter(
            AssetCanonical.asset_type == "dns_record", AssetCanonical.value == tp)
    }
    assert set(rows) == {"A", "TXT"}
    own, hid_id = rows["A"], rows["TXT"].id
    www_id = env.db.query(AssetCanonical.id).filter(
        AssetCanonical.asset_type == "dns_record", AssetCanonical.value == www).one()[0]
    env.link(ours, own)
    # The only edge from www goes to the hidden row.
    env.db.add(AssetEdge(source_type="asset_canonical", source_id=www_id, target_type="asset_canonical",
                         target_id=hid_id, edge_type="resolves_to", edge_metadata={"record_type": "CNAME"}))
    env.db.commit()
    assert env.db.query(AssetEdge).filter(AssetEdge.source_id == www_id).count() == 1

    engagement = make_engagement(env.db, "pre_close")
    closed = Target(id=uuid.uuid4(), type="domain", value=_CLOSED, engagement_id=engagement.id)
    env.db.add(closed)
    env.db.commit()
    closed_id, engagement_id, own_id = closed.id, engagement.id, own.id

    def drop_closed():
        env.db.query(TargetAssetLink).filter(TargetAssetLink.target_id == closed_id).delete(
            synchronize_session=False)
        env.db.query(Target).filter(Target.id == closed_id).delete(synchronize_session=False)
        env.db.commit()
        cleanup_engagement(env.db, engagement_id)

    env.cleanups.append(drop_closed)
    env.db.add(TargetAssetLink(target_id=closed_id, asset_canonical_id=hid_id, first_linked_at=T0, last_observed_at=T1))
    env.db.commit()

    viewer = env.db.get(User, env.w.user("viewer").id)

    def readable(user, asset_id):
        return env.db.query(AssetCanonical.id).filter(
            AssetCanonical.id == asset_id, read_scope.asset_clause(user, AssetCanonical)).count() == 1

    # Reached: the asset under test passes the viewer's read scope, its second row does not.
    assert readable(viewer, own_id) and not readable(viewer, hid_id)
    assert readable(viewer, www_id) and readable(env.admin, hid_id)

    def host_hop(body):
        return [x for x in body["chains"][0]["hops"] if x["kind"] == "host"][0]

    u = _dump(env.build(own))
    env.db.expire_all()
    h = _dump(build_attribution(env.db, viewer, own))
    assert [(c["value"], c["distance"]) for c in host_hop(u)["candidates"] if c["value"] == www] == [(www, 1)]
    assert host_hop(h)["candidates"] == []
    assert str(hid_id) not in list(_strings(h)) and www not in list(_strings(h))

    env.db.rollback()
    env.db.query(TargetAssetLink).filter(TargetAssetLink.asset_canonical_id == hid_id).delete(synchronize_session=False)
    env.db.query(AssetEdge).filter(or_(AssetEdge.source_id == hid_id, AssetEdge.target_id == hid_id)).delete(
        synchronize_session=False)
    env.db.query(AssetState).filter(AssetState.asset_canonical_id == hid_id).delete(synchronize_session=False)
    env.db.query(AssetCanonical).filter(AssetCanonical.id == hid_id).delete(synchronize_session=False)
    env.db.commit()
    d = _dump(env.build(own))
    assert host_hop(d)["candidates"] == []
    assert h == d
