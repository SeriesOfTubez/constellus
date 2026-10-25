"""ARIN signals (planning#278 S3b1 part C): `arin.record_arin`, the runner's
`rir_for_claimed` and the post-claim trigger.

`record_arin` tests build `ArinCollection` objects directly (pure data). One
end-to-end test runs the real collector through a patched
`rir_fetch.connector_get` router. Documentation space and synthetic handles
only; sub-/24 values are derived from the /24 (test_docaddr_guard).

Run with:  scripts/test.sh app/tests/test_org_discovery_arin_signals.py
"""

import ipaddress
import uuid

import pytest
from sqlalchemy import func, select

from app.core.database import SessionLocal
from app.models.rir_lookup_cache import RirLookupCache
from app.models.scope_candidate import ScopeCandidate, ScopeSignal
from app.models.target import Target
from app.services.org_discovery import arin, runner
from app.services.org_discovery import candidates as cd
from app.services.org_discovery import rir_fetch as rf
from app.services.org_discovery import strength as strength_sql
from app.tests._org_world import World, hexid
from app.tests.test_org_discovery_arin import (
    Router, children_body, net_body, setup_org, setup_poc,
)
from app.tests.test_org_discovery_asn_cidr import _Meta

REAL_RIR_COLLECT = True  # the autouse stub is off; every test here that reaches the runner patches its own seam

A24 = ipaddress.ip_network("198.51.100.0/24")
B24 = ipaddress.ip_network("203.0.113.0/24")
A24S, B24S = str(A24), str(B24)
S25 = [str(n) for n in A24.subnets(new_prefix=25)]
S26 = [str(n) for n in A24.subnets(new_prefix=26)]


@pytest.fixture
def w():
    world = World()
    try:
        yield world
    finally:
        world.close()


@pytest.fixture
def cache_clean():
    yield
    db = SessionLocal()
    try:
        db.query(RirLookupCache).filter(RirLookupCache.path.ilike("%arns%")).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()


@pytest.fixture
def t():
    return "ARNS" + hexid()[:6].upper()


def _dom(t) -> str:
    return f"{t.lower()}.example.com"


def _claimed(w, root, value):
    c = w.candidate(root, value=value)
    result = cd.claim(w.db, candidate_id=c.id, user=w.user())
    w.track_target(result.target.value)
    w.db.commit()
    return c


def _net(handle, pieces, *, org="ORG", blocks=None, excluded=(), failed=None):
    blocks = blocks or (arin.RawBlock(str(A24.network_address), "24", "DA"),)
    return arin.NetResult(handle, org, tuple(blocks), tuple(pieces), tuple(excluded), failed)


def _org(handle, asns=(), nets=()):
    return arin.OrgResult(
        handle=handle, asns=tuple(asns), nets=tuple(nets), asns_truncated=False, nets_truncated=False,
        skipped_nested=0, skipped_not_held=0, skipped_type=0, invalid=0,
    )


def _poc(handle, orgs, *, validated=True, domain="example.com", funcs=("AD",)):
    return arin.MatchedPoc(
        handle=handle, validated=validated, email_domains=(domain,),
        org_links=tuple((o, tuple(funcs)) for o in orgs),
    )


def _coll(domain, pocs, orgs):
    return arin.ArinCollection(
        domain=domain, pocs_listed=len(pocs), pocs_truncated=False, pocs_not_exact=0,
        matched=tuple(pocs), orgs={o.handle: o for o in orgs},
    )


def _cand(db, root_id, value, kind):
    return db.execute(select(ScopeCandidate).where(
        ScopeCandidate.root_entity_id == root_id, ScopeCandidate.kind == kind, ScopeCandidate.value == value
    )).scalar_one_or_none()


def _strength(db, cand):
    s = strength_sql.strength_subquery(candidate_ids=[cand.id])
    row = db.execute(select(s.strength.label("strength"), s.proposable.label("proposable"))).one()
    return row.strength, bool(row.proposable)


def _signal_count(db, root_id):
    return db.execute(
        select(func.count()).select_from(ScopeSignal).join(ScopeCandidate, ScopeCandidate.id == ScopeSignal.candidate_id)
        .where(ScopeCandidate.root_entity_id == root_id)
    ).scalar_one()


def _types(db, cand):
    return sorted(db.execute(select(ScopeSignal.signal_type).where(ScopeSignal.candidate_id == cand.id)).scalars())


def _setup(w, t):
    root = w.ours()
    claimed = _claimed(w, root, _dom(t))
    return root, claimed


# ── tier ─────────────────────────────────────────────────────────────────────


def test_a_validated_poc_gives_strong_signals_on_the_asn_and_every_piece(w, t):
    root, claimed = _setup(w, t)
    org = f"{t}-ORG"
    coll = _coll(claimed.value, [_poc(f"{t}-P1", [org])], [_org(org, ["AS64500"], [_net(f"{t}-N1", [S25[0], S25[1]])])])
    r = arin.record_arin(w.db, claimed=claimed, collection=coll)
    w.db.commit()
    assert (r.signals_recorded, r.signals_resighted, len(r.created_candidate_ids)) == (3, 0, 3)
    for kind, value in (("asn", "AS64500"), ("cidr", S25[0]), ("cidr", S25[1])):
        c = _cand(w.db, root.id, value, kind)
        assert c is not None, value
        assert (c.rir, c.rir_handle) == ("arin", org)
        assert _types(w.db, c) == ["rir_contact_email_claimed"]
        assert _strength(w.db, c) == ("strong", True)
    sig = w.db.execute(select(ScopeSignal).where(ScopeSignal.candidate_id == _cand(w.db, root.id, "AS64500", "asn").id)).scalar_one()
    assert sig.matched_values == ["example.com"] and sig.anchor_candidate_id == claimed.id
    assert "AS64500" in sig.quote and "(validated)" in sig.quote


def test_an_unvalidated_poc_gives_a_supporting_lead_that_is_not_proposable(w, t):
    root, claimed = _setup(w, t)
    org = f"{t}-ORG"
    coll = _coll(claimed.value, [_poc(f"{t}-P1", [org], validated=False)], [_org(org, ["AS64500"], [])])
    r = arin.record_arin(w.db, claimed=claimed, collection=coll)
    w.db.commit()
    assert r.signals_recorded == 1
    c = _cand(w.db, root.id, "AS64500", "asn")
    assert c is not None and _types(w.db, c) == ["rir_contact_email_unvalidated"]
    assert _strength(w.db, c) == ("lead", False)
    assert "(not validated)" in w.db.execute(select(ScopeSignal.quote).where(ScopeSignal.candidate_id == c.id)).scalar_one()


def test_an_org_holding_nothing_gives_no_signal(w, t):
    root, claimed = _setup(w, t)
    empty, full = f"{t}-EMPTY", f"{t}-FULL"
    failed_only = _net(f"{t}-NF", [], failed="too_deep")
    pocs = [_poc(f"{t}-P1", [empty]), _poc(f"{t}-P2", [full])]
    coll = _coll(claimed.value, pocs, [_org(empty, [], [failed_only]), _org(full, ["AS64501"], [])])
    r = arin.record_arin(w.db, claimed=claimed, collection=coll)
    w.db.commit()
    # the path was reached (the POC matched, the other org recorded) and the empty org gave nothing
    assert len(coll.matched) == 2 and r.signals_recorded == 1
    assert r.orgs_holding_nothing == 1
    assert _cand(w.db, root.id, "AS64501", "asn") is not None
    assert w.db.execute(select(func.count()).select_from(ScopeCandidate).where(
        ScopeCandidate.root_entity_id == root.id, ScopeCandidate.rir_handle == empty)).scalar_one() == 0


@pytest.mark.parametrize("reason", ["fetch_failed", "budget", "children_truncated", "too_deep", "too_many_pieces", "bad_block", "bad_child"])
def test_a_failed_net_gives_no_candidate_while_another_net_of_the_org_still_records(w, t, reason):
    root, claimed = _setup(w, t)
    org = f"{t}-ORG"
    bad_block = (arin.RawBlock(str(B24.network_address), "24", "DA"),)
    bad = _net(f"{t}-NB", [], blocks=bad_block, failed=reason)
    good = _net(f"{t}-NG", [S25[0]])
    coll = _coll(claimed.value, [_poc(f"{t}-P1", [org])], [_org(org, [], [bad, good])])
    r = arin.record_arin(w.db, claimed=claimed, collection=coll)
    w.db.commit()
    assert r.signals_recorded == 1 and r.nets_failed == {reason: 1}
    assert _cand(w.db, root.id, S25[0], "cidr") is not None
    assert _cand(w.db, root.id, B24S, "cidr") is None


# ── idempotence, conflict, context ───────────────────────────────────────────


def test_a_rerun_with_the_same_collection_resights_and_adds_no_rows(w, t):
    root, claimed = _setup(w, t)
    org = f"{t}-ORG"
    ex = arin.ExcludedChild(f"{t}-C1", "org", "OTHER-1", (S25[1],))
    coll = _coll(claimed.value, [_poc(f"{t}-P1", [org])], [_org(org, ["AS64500"], [_net(f"{t}-N1", [S25[0]], excluded=[ex])])])
    before = _signal_count(w.db, root.id)
    first = arin.record_arin(w.db, claimed=claimed, collection=coll)
    w.db.commit()
    rows = _signal_count(w.db, root.id)
    assert first.signals_recorded == 2 and rows == before + 2
    second = arin.record_arin(w.db, claimed=claimed, collection=coll)
    w.db.commit()
    assert second.signals_resighted == first.signals_recorded and second.signals_recorded == 0
    assert second.created_candidate_ids == []
    assert _signal_count(w.db, root.id) == rows


def test_an_existing_candidate_under_another_handle_is_a_conflict_and_the_rest_still_records(w, t):
    root, claimed = _setup(w, t)
    org = f"{t}-ORG"
    ev = w.evidence_row()
    cd.record_signal(
        w.db, root_entity_id=root.id, kind="cidr", value=S25[0], rir="arin", rir_handle="OTHER-1",
        signal_type="person_evidence", anchor_kind="person", via_entity_id=root.id, evidence_id=ev.id,
        quote=f"net {A24.network_address}",
    )
    w.db.commit()
    coll = _coll(claimed.value, [_poc(f"{t}-P1", [org])], [_org(org, ["AS64500"], [_net(f"{t}-N1", [S25[0], S25[1]])])])
    r = arin.record_arin(w.db, claimed=claimed, collection=coll)
    w.db.commit()
    assert r.holder_conflict == 1 and r.signals_recorded == 2 and r.invalid == 0
    assert _cand(w.db, root.id, "AS64500", "asn") is not None and _cand(w.db, root.id, S25[1], "cidr") is not None
    held = _cand(w.db, root.id, S25[0], "cidr")
    assert held.rir_handle == "OTHER-1" and _types(w.db, held) == ["person_evidence"]
    assert w.db.execute(select(func.count()).select_from(ScopeCandidate).where(ScopeCandidate.root_entity_id == root.id)).scalar_one() == 4


def test_an_excluded_child_that_is_already_a_candidate_gets_a_context_signal(w, t):
    root, claimed = _setup(w, t)
    org = f"{t}-ORG"
    ev = w.evidence_row()
    child = cd.record_signal(
        w.db, root_entity_id=root.id, kind="cidr", value=S25[1], rir="arin", rir_handle="CHILD-ORG",
        signal_type="person_evidence", anchor_kind="person", via_entity_id=root.id, evidence_id=ev.id,
        quote=f"net {ipaddress.ip_network(S25[1]).network_address}",
    ).candidate
    w.db.commit()
    ex = arin.ExcludedChild(f"{t}-C1", "org", "CHILD-ORG", (S25[1],))
    # an UNVALIDATED poc: context is recorded whatever the validation
    coll = _coll(claimed.value, [_poc(f"{t}-P1", [org], validated=False)], [_org(org, [], [_net(f"{t}-N1", [S25[0]], excluded=[ex])])])
    r = arin.record_arin(w.db, claimed=claimed, collection=coll)
    w.db.commit()
    assert (r.context_recorded, r.context_no_candidate) == (1, 0)
    assert _types(w.db, child) == ["person_evidence", "rir_reassigned_elsewhere"]
    q = w.db.execute(select(ScopeSignal.quote).where(
        ScopeSignal.candidate_id == child.id, ScopeSignal.signal_type == "rir_reassigned_elsewhere")).scalar_one()
    assert q == f"{S25[1]} is inside ARIN net {t}-N1 held by org {org} but is reassigned to org CHILD-ORG"
    assert (child.rir, child.rir_handle) == ("arin", "CHILD-ORG")


def test_an_excluded_child_held_under_another_registry_gets_no_context_signal(w, t):
    root, claimed = _setup(w, t)
    org = f"{t}-ORG"
    ev = w.evidence_row()
    child = cd.record_signal(
        w.db, root_entity_id=root.id, kind="cidr", value=S25[1], rir="ripe", rir_handle="ORG-CHILD1-RIPE",
        signal_type="person_evidence", anchor_kind="person", via_entity_id=root.id, evidence_id=ev.id,
        quote=f"net {ipaddress.ip_network(S25[1]).network_address}",
    ).candidate
    w.db.commit()
    ex = arin.ExcludedChild(f"{t}-C1", "org", "CHILD-ORG", (S25[1],))
    coll = _coll(claimed.value, [_poc(f"{t}-P1", [org])], [_org(org, [], [_net(f"{t}-N1", [S25[0]], excluded=[ex])])])
    r = arin.record_arin(w.db, claimed=claimed, collection=coll)
    w.db.commit()
    assert r.signals_recorded == 1  # the path was reached: the net's own piece recorded
    assert (r.context_recorded, r.context_no_candidate) == (0, 1)
    assert _types(w.db, child) == ["person_evidence"]


def test_an_excluded_child_that_is_not_a_candidate_is_counted_and_creates_nothing(w, t):
    root, claimed = _setup(w, t)
    org = f"{t}-ORG"
    ex = arin.ExcludedChild(f"{t}-C1", "customer", None, (S25[1],))
    coll = _coll(claimed.value, [_poc(f"{t}-P1", [org])], [_org(org, [], [_net(f"{t}-N1", [S25[0]], excluded=[ex])])])
    r = arin.record_arin(w.db, claimed=claimed, collection=coll)
    w.db.commit()
    assert r.signals_recorded == 1  # the path was reached: the net's own piece recorded
    assert (r.context_recorded, r.context_no_candidate) == (0, 1)
    assert _cand(w.db, root.id, S25[1], "cidr") is None


def test_a_candidate_that_is_not_claimed_gives_an_empty_result(w, t):
    root = w.ours()
    open_c = w.candidate(root, value=_dom(t))
    org = f"{t}-ORG"
    coll = _coll(open_c.value, [_poc(f"{t}-P1", [org])], [_org(org, ["AS64500"], [])])
    r = arin.record_arin(w.db, claimed=open_c, collection=coll)
    assert r == arin.ArinRecordResult()
    assert _cand(w.db, root.id, "AS64500", "asn") is None
    claimed = _claimed(w, root, _dom(t + "X"))
    assert arin.record_arin(w.db, claimed=claimed, collection=coll).signals_recorded == 1  # control: claimed does record


# ── cascade ──────────────────────────────────────────────────────────────────


def test_claiming_the_asn_claims_the_pieces_as_cidr_targets(w, t):
    meta = _Meta(w.db)
    had = meta.db.get(__import__("app.models.cloud_range", fromlist=["CloudRangeMeta"]).CloudRangeMeta, True) is not None
    meta.add()
    try:
        root, claimed = _setup(w, t)
        org = f"{t}-ORG"
        coll = _coll(claimed.value, [_poc(f"{t}-P1", [org])], [_org(org, ["AS64500"], [_net(f"{t}-N1", [S25[0], S25[1]])])])
        arin.record_arin(w.db, claimed=claimed, collection=coll)
        w.db.commit()
        asn = _cand(w.db, root.id, "AS64500", "asn")
        for v in (S25[0], S25[1]):
            w.track_target(v)
        result = cd.claim(w.db, candidate_id=asn.id, user=w.user())
        w.db.commit()
        assert {p.candidate.value for p in result.prefixes} == {S25[0], S25[1]}
        for v in (S25[0], S25[1]):
            c = _cand(w.db, root.id, v, "cidr")
            tgt = w.db.get(Target, c.target_id)
            assert (c.status, tgt.type, tgt.value) == ("claimed", "cidr", v)
    finally:
        w.db.rollback()
        if not had:
            meta.remove()


# ── runner ───────────────────────────────────────────────────────────────────


def _wire(router, t, *, status="PV"):
    nh = f"{t}-N1"
    ph, oh, d = setup_poc(router, t, status=status)
    setup_org(router, oh, ["AS64500"], [nh])
    router.add(f"net/{nh}", net_body(nh, [A24S], ("orgRef", oh)))
    router.add(f"net/{nh}/children", children_body([]))
    return oh, d


def _fresh(root_id):
    db = SessionLocal()
    try:
        return sorted(
            (c.kind, c.value, c.rir, c.rir_handle) for c in db.execute(
                select(ScopeCandidate).where(ScopeCandidate.root_entity_id == root_id, ScopeCandidate.kind != "domain")
            ).scalars()
        )
    finally:
        db.close()


def test_runner_end_to_end_commits_signals_visible_from_a_fresh_session(w, t, monkeypatch, cache_clean):
    router = Router()
    monkeypatch.setattr(rf, "connector_get", router)
    monkeypatch.setattr(
        runner, "_rir_collect", lambda db, domain: arin.collect(db, domain, rf.Budget()),
    )
    root = w.ours()
    oh, d = _wire(router, t)
    claimed = _claimed(w, root, d)
    r = runner.rir_for_claimed(claimed.id)
    assert router.calls  # the transport was reached
    assert r.signals_recorded == 2 and len(r.created_candidate_ids) == 2
    assert _fresh(root.id) == [("asn", "AS64500", "arin", oh), ("cidr", A24S, "arin", oh)]


def test_runner_rolls_back_the_signal_step_but_keeps_the_cache(w, t, monkeypatch, cache_clean):
    router = Router()
    monkeypatch.setattr(rf, "connector_get", router)
    monkeypatch.setattr(runner, "_rir_collect", lambda db, domain: arin.collect(db, domain, rf.Budget()))

    def boom(*a, **k):
        raise RuntimeError("record exploded")

    monkeypatch.setattr(arin, "record_arin", boom)
    root = w.ours()
    oh, d = _wire(router, t)
    claimed = _claimed(w, root, d)
    r = runner.rir_for_claimed(claimed.id)
    assert router.calls  # collect ran
    assert r == arin.ArinRecordResult()
    assert _fresh(root.id) == []
    db = SessionLocal()
    try:
        cached = db.query(RirLookupCache).filter(RirLookupCache.path.ilike(f"%{t}%")).count()
    finally:
        db.close()
    assert cached > 0


def test_runner_skips_a_candidate_that_is_not_claimed(w, t, monkeypatch):
    seen = []
    monkeypatch.setattr(runner, "_rir_collect", lambda db, domain: seen.append(domain))
    root = w.ours()
    open_c = w.candidate(root, value=_dom(t))
    assert runner.rir_for_claimed(open_c.id) == arin.ArinRecordResult()
    assert seen == []
    assert runner.rir_for_claimed(uuid.uuid4()) == arin.ArinRecordResult()
    claimed = _claimed(w, root, _dom(t + "Y"))
    monkeypatch.setattr(runner, "_rir_collect", lambda db, domain: arin.ArinCollection(
        domain=domain, pocs_listed=0, pocs_truncated=False, pocs_not_exact=0, matched=()))
    runner.rir_for_claimed(claimed.id)  # control: a claimed one reaches the seam


def test_verify_after_claim_calls_rir_for_claimed_and_swallows_its_failure(w, t, monkeypatch):
    root = w.ours()
    claimed = _claimed(w, root, _dom(t))
    calls: list = []
    monkeypatch.setattr(runner, "rir_for_claimed", lambda cid: calls.append(cid))
    runner.verify_after_claim(claimed.id)
    assert calls == [claimed.id]

    def boom(cid):
        raise RuntimeError("rir exploded")

    monkeypatch.setattr(runner, "rir_for_claimed", boom)
    assert runner.verify_after_claim(claimed.id).pairs_checked == 0  # did not raise
