"""RIPE signals (planning#278 S3b2 slice C): `ripe.record_ripe` and the runner's
two-registry `rir_for_claimed`.

`record_ripe` tests build `RipeCollection` objects directly (pure data). One
end-to-end test runs the real collector through a patched
`rir_fetch.connector_get` router in the real RIPE wire shape. Documentation
space and synthetic handles only; sub-/24 values are derived from the /24
(test_docaddr_guard). The conftest autouse stub stays ON for this module, so
no test here can reach a registry unless it patches a seam itself.

Run with:  scripts/test.sh app/tests/test_org_discovery_ripe_signals.py
"""

import ast
import inspect
import ipaddress
import json
import uuid

import pytest
from sqlalchemy import func, select

from app.core.database import SessionLocal
from app.models.evidence import EvidenceBlob, EvidenceFetch
from app.models.rir_lookup_cache import RirLookupCache
from app.models.scope_candidate import ScopeCandidate, ScopeSignal
from app.services.org_discovery import arin, ripe, runner
from app.services.org_discovery import candidates as cd
from app.services.org_discovery import rir_fetch as rf
from app.tests._org_world import World, hexid
from app.tests.test_org_discovery_arin_signals import _cand, _claimed, _dom, _signal_count, _strength, _types
from app.tests.test_org_discovery_ripe import (
    Router, ft_doc, irange, net4, organisation, res as wire_res,
)

A24 = ipaddress.ip_network("198.51.100.0/24")
B24 = ipaddress.ip_network("203.0.113.0/24")
S25 = [str(n) for n in A24.subnets(new_prefix=25)]
S26 = [str(n) for n in A24.subnets(new_prefix=26)]
B24S = str(B24)


@pytest.fixture
def w():
    world = World()
    try:
        yield world
    finally:
        world.close()


@pytest.fixture
def t():
    return "RPS" + hexid()[:6].upper()


@pytest.fixture
def cache_clean():
    def _clean():
        db = SessionLocal()
        try:
            db.query(RirLookupCache).filter(RirLookupCache.rir == "ripe").delete(synchronize_session=False)
            db.commit()
        finally:
            db.close()

    _clean()
    yield
    _clean()


def _setup(w, t):
    root = w.ours()
    return root, _claimed(w, root, _dom(t))


def _contact(handle, domain, otype="role"):
    return ripe.MatchedContact(handle, otype, (domain,))


def _r(otype="inetnum", pk=None, *, holder="ORG-TEST1", kind="org", via=("RL1-TEST",), pieces=(), asn=None,
       excluded=(), nested=(), failed=None, status="ASSIGNED PA", via_attributes=("admin-c",)):
    return ripe.RipeResource(
        object_type=otype, primary_key=pk or (irange(A24) if otype == "inetnum" else "AS64500"), status=status,
        holder=holder, holder_kind=kind, via=tuple(via), via_attributes=tuple(via_attributes), asn=asn,
        pieces=tuple(pieces), excluded=tuple(excluded), nested=tuple(nested), nested_not_collected=0, failed=failed,
    )


def _coll(domain, matched, resources):
    return ripe.RipeCollection(
        domain=domain, docs_found=len(matched), docs_seen=len(matched), fulltext_truncated=False, docs_other_type=0,
        contacts_not_exact=0, matched=tuple(matched), resources=tuple(resources), orgs_followed=0, fetch_failed=0,
        budget_exhausted=False, invalid_handles=0, invalid=0, skipped_status=0, skipped_source=0,
    )


def _one_net_coll(claimed, pieces=(S25[0], S25[1]), holder="ORG-TEST1", **kw):
    return _coll(claimed.value, [_contact("RL1-TEST", claimed.value)], [_r(holder=holder, pieces=pieces, **kw)])


def _evidence_count(db, t):
    return db.execute(
        select(func.count()).select_from(EvidenceFetch).where(EvidenceFetch.source_url.ilike(f"%/ripe/%{t.lower()}%"))
    ).scalar_one()


# ── tier ─────────────────────────────────────────────────────────────────────


def test_an_org_held_inetnum_gives_one_supporting_signal_per_piece_and_is_not_proposable(w, t):
    root, claimed = _setup(w, t)
    r = ripe.record_ripe(w.db, claimed=claimed, collection=_one_net_coll(claimed))
    w.db.commit()
    assert (r.signals_recorded, r.signals_resighted, len(r.created_candidate_ids)) == (2, 0, 2)
    for piece in (S25[0], S25[1]):
        c = _cand(w.db, root.id, piece, "cidr")
        assert c is not None, piece
        assert (c.rir, c.rir_handle) == ("ripe", "ORG-TEST1")
        assert _types(w.db, c) == ["rir_contact_email_unvalidated"]
        assert _strength(w.db, c) == ("lead", False)
    sig = w.db.execute(select(ScopeSignal).where(ScopeSignal.candidate_id == _cand(w.db, root.id, S25[0], "cidr").id)).scalar_one()
    assert sig.matched_values == [claimed.value] and sig.anchor_candidate_id == claimed.id
    assert sig.quote.startswith(f"{S25[0]} is in RIPE inetnum ")


def test_an_aut_num_gives_an_asn_candidate_with_a_supporting_signal(w, t):
    root, claimed = _setup(w, t)
    coll = _coll(claimed.value, [_contact("RL1-TEST", claimed.value)], [_r("aut-num", "AS64500", asn="AS64500", status="ASSIGNED")])
    r = ripe.record_ripe(w.db, claimed=claimed, collection=coll)
    w.db.commit()
    assert r.signals_recorded == 1
    c = _cand(w.db, root.id, "AS64500", "asn")
    assert (c.rir, c.rir_handle) == ("ripe", "ORG-TEST1")
    assert _types(w.db, c) == ["rir_contact_email_unvalidated"] and _strength(w.db, c) == ("lead", False)


def test_a_contact_held_resource_uses_the_contact_handle_as_the_holder(w, t):
    root, claimed = _setup(w, t)
    coll = _coll(claimed.value, [_contact("RL1-TEST", claimed.value)],
                 [_r(holder="RL1-TEST", kind="contact", pieces=(S25[0],))])
    ripe.record_ripe(w.db, claimed=claimed, collection=coll)
    w.db.commit()
    c = _cand(w.db, root.id, S25[0], "cidr")
    assert (c.rir, c.rir_handle) == ("ripe", "RL1-TEST")


def test_two_contacts_on_one_resource_give_one_signal_per_value_with_both_in_the_evidence(w, t):
    root, claimed = _setup(w, t)
    coll = _coll(claimed.value, [_contact("RL1-TEST", claimed.value), _contact("RL2-TEST", "sub." + claimed.value)],
                 [_r(via=("RL2-TEST", "RL1-TEST", "ORG-UNMATCHED"), pieces=(S25[0],))])
    r = ripe.record_ripe(w.db, claimed=claimed, collection=coll)
    w.db.commit()
    assert r.signals_recorded == 1
    c = _cand(w.db, root.id, S25[0], "cidr")
    sig = w.db.execute(select(ScopeSignal).where(ScopeSignal.candidate_id == c.id)).scalar_one()
    assert sig.matched_values == sorted([claimed.value, "sub." + claimed.value])
    assert "RL1-TEST, RL2-TEST" in sig.quote and "ORG-UNMATCHED" not in sig.quote
    body = json.loads(w.db.get(EvidenceBlob, w.db.get(EvidenceFetch, sig.evidence_id).sha256).content)
    assert [v["handle"] for v in body["via"]] == ["RL1-TEST", "RL2-TEST"]
    assert body["via_handles"] == ["ORG-UNMATCHED", "RL1-TEST", "RL2-TEST"]
    assert body["rule"] == "rir_contact_email_unvalidated" and body["rir"] == "ripe"


def test_evidence_and_quote_carry_no_email_local_part(w, t):
    root, claimed = _setup(w, t)
    ex = arin.ExcludedChild("CHILD-1", "org", "ORG-CHILD1", (S25[1],))
    r = ripe.record_ripe(w.db, claimed=claimed, collection=_one_net_coll(claimed, pieces=(S25[0],), excluded=(ex,)))
    w.db.commit()
    assert r.signals_recorded == 1
    c = _cand(w.db, root.id, S25[0], "cidr")
    sig = w.db.execute(select(ScopeSignal).where(ScopeSignal.candidate_id == c.id)).scalar_one()
    content = w.db.get(EvidenceBlob, w.db.get(EvidenceFetch, sig.evidence_id).sha256).content.decode()
    assert "@" not in content and "@" not in sig.quote
    assert "more-specific(s) held elsewhere are excluded" in sig.quote
    body = json.loads(content)
    assert body["excluded"] == [{"handle": "CHILD-1", "holder_kind": "org", "holder_handle": "ORG-CHILD1", "prefixes": [S25[1]]}]
    assert body["nested"] == [] and body["primary_key"] == irange(A24)


def test_a_long_contact_list_is_truncated_but_the_needle_leads(w, t):
    root, claimed = _setup(w, t)
    via = tuple(f"RL{i:03d}-" + "X" * 55 for i in range(60))
    coll = _coll(claimed.value, [_contact(h, claimed.value) for h in via], [_r(via=via, pieces=(S25[0],))])
    ripe.record_ripe(w.db, claimed=claimed, collection=coll)
    w.db.commit()
    q = w.db.execute(select(ScopeSignal.quote).where(ScopeSignal.candidate_id == _cand(w.db, root.id, S25[0], "cidr").id)).scalar_one()
    assert len(q) <= 2000 and q.startswith(S25[0]) and "..." in q and q.endswith(f"have an email at {claimed.value}")


# ── idempotence, failure, nothing ────────────────────────────────────────────


def test_a_rerun_resights_and_adds_no_signal_or_evidence_rows(w, t):
    root, claimed = _setup(w, t)
    ex = arin.ExcludedChild("CHILD-1", "org", "ORG-CHILD1", (S25[1],))
    coll = _one_net_coll(claimed, pieces=(S25[0],), excluded=(ex,))
    before = _signal_count(w.db, root.id)
    first = ripe.record_ripe(w.db, claimed=claimed, collection=coll)
    w.db.commit()
    rows, evid = _signal_count(w.db, root.id), _evidence_count(w.db, t)
    assert first.signals_recorded == 1 and rows == before + 1 and evid == 1
    second = ripe.record_ripe(w.db, claimed=claimed, collection=coll)
    w.db.commit()
    assert (second.signals_recorded, second.signals_resighted) == (0, 1)
    assert second.created_candidate_ids == []
    assert _signal_count(w.db, root.id) == rows and _evidence_count(w.db, t) == evid


def test_evidence_is_deterministic_whatever_order_the_via_handles_arrive_in(w, t):
    root, claimed = _setup(w, t)
    m = [_contact("RL1-TEST", claimed.value), _contact("RL2-TEST", claimed.value)]
    ripe.record_ripe(w.db, claimed=claimed, collection=_coll(
        claimed.value, m, [_r(via=("RL1-TEST", "RL2-TEST"), pieces=(S25[0],))]))
    w.db.commit()
    evid = _evidence_count(w.db, t)
    second = ripe.record_ripe(w.db, claimed=claimed, collection=_coll(
        claimed.value, list(reversed(m)), [_r(via=("RL2-TEST", "RL1-TEST"), pieces=(S25[0],))]))
    w.db.commit()
    assert second.signals_resighted == 1 and _evidence_count(w.db, t) == evid == 1


def test_a_failed_resource_gives_no_signal_is_counted_and_the_next_still_records(w, t):
    root, claimed = _setup(w, t)
    bad = _r(pk=irange(B24), holder="ORG-BAD", failed="too_many_pieces")
    good = _r(pieces=(S25[0],))
    coll = _coll(claimed.value, [_contact("RL1-TEST", claimed.value)], [bad, good])
    r = ripe.record_ripe(w.db, claimed=claimed, collection=coll)
    w.db.commit()
    assert r.resources_failed == {"too_many_pieces": 1}
    assert r.signals_recorded == 1  # the path was reached: the good resource recorded
    assert _cand(w.db, root.id, S25[0], "cidr") is not None and _cand(w.db, root.id, B24S, "cidr") is None
    assert w.db.execute(select(func.count()).select_from(ScopeCandidate).where(
        ScopeCandidate.root_entity_id == root.id, ScopeCandidate.rir_handle == "ORG-BAD")).scalar_one() == 0
    assert r.holders_holding_nothing == 1  # the failed resource's holder holds nothing proposable


def test_a_failed_resource_never_records_even_if_it_carries_pieces(w, t):
    # The collector guarantees pieces == () on failure; the recorder must not depend on that.
    root, claimed = _setup(w, t)
    bad = _r(pk=irange(B24), holder="ORG-BAD", failed="bad_child", pieces=(B24S,))
    good = _r(pieces=(S25[0],))
    r = ripe.record_ripe(w.db, claimed=claimed, collection=_coll(claimed.value, [_contact("RL1-TEST", claimed.value)], [bad, good]))
    w.db.commit()
    assert r.signals_recorded == 1 and r.resources_failed == {"bad_child": 1}
    assert _cand(w.db, root.id, B24S, "cidr") is None


def test_a_holder_holding_nothing_is_counted_and_gives_no_signal(w, t):
    root, claimed = _setup(w, t)
    empty = _r(pk=irange(B24), holder="ORG-EMPTY", pieces=())
    full = _r(pieces=(S25[0],))
    r = ripe.record_ripe(w.db, claimed=claimed, collection=_coll(claimed.value, [_contact("RL1-TEST", claimed.value)], [empty, full]))
    w.db.commit()
    assert r.signals_recorded == 1 and r.holders_holding_nothing == 1
    assert w.db.execute(select(func.count()).select_from(ScopeCandidate).where(
        ScopeCandidate.root_entity_id == root.id, ScopeCandidate.rir_handle == "ORG-EMPTY")).scalar_one() == 0


def test_the_collections_counters_are_copied_through(w, t):
    root, claimed = _setup(w, t)
    base = _one_net_coll(claimed)
    coll = ripe.RipeCollection(**{**base.__dict__, "docs_found": 9, "fulltext_truncated": True, "contacts_not_exact": 3,
                                  "fetch_failed": 2, "budget_exhausted": True, "invalid_handles": 4,
                                  "skipped_status": 5, "skipped_source": 6})
    r = ripe.record_ripe(w.db, claimed=claimed, collection=coll)
    assert (r.docs_found, r.fulltext_truncated, r.contacts_not_exact, r.fetch_failed, r.budget_exhausted,
            r.invalid_handles, r.skipped_status, r.skipped_source) == (9, True, 3, 2, True, 4, 5, 6)


def test_a_candidate_that_is_not_claimed_gives_an_empty_result(w, t):
    root = w.ours()
    open_c = w.candidate(root, value=_dom(t))
    coll = _one_net_coll(open_c)
    assert ripe.record_ripe(w.db, claimed=open_c, collection=coll) == ripe.RipeRecordResult()
    assert _cand(w.db, root.id, S25[0], "cidr") is None
    claimed = _claimed(w, root, _dom(t + "X"))
    assert ripe.record_ripe(w.db, claimed=claimed, collection=_one_net_coll(claimed)).signals_recorded == 2  # control


# ── conflict ─────────────────────────────────────────────────────────────────


def test_a_prefix_held_under_another_ripe_holder_is_a_conflict_and_the_next_resource_still_records(w, t):
    root, claimed = _setup(w, t)
    ev = w.evidence_row()
    cd.record_signal(
        w.db, root_entity_id=root.id, kind="cidr", value=S25[0], rir="ripe", rir_handle="ORG-OTHER",
        signal_type="person_evidence", anchor_kind="person", via_entity_id=root.id, evidence_id=ev.id,
        quote=f"net {A24.network_address}",
    )
    w.db.commit()
    first = _r(holder="ORG-TEST1", pieces=(S25[0],))
    second = _r(pk=irange(B24), holder="ORG-TEST2", pieces=(B24S,))
    r = ripe.record_ripe(w.db, claimed=claimed, collection=_coll(claimed.value, [_contact("RL1-TEST", claimed.value)], [first, second]))
    w.db.commit()
    assert r.holder_conflict == 1 and r.signals_recorded == 1 and r.invalid == 0
    assert _cand(w.db, root.id, B24S, "cidr") is not None
    held = _cand(w.db, root.id, S25[0], "cidr")
    assert held.rir_handle == "ORG-OTHER" and _types(w.db, held) == ["person_evidence"]


# ── context ──────────────────────────────────────────────────────────────────


def _existing(w, root, value, rir, handle):
    ev = w.evidence_row()
    c = cd.record_signal(
        w.db, root_entity_id=root.id, kind="cidr", value=value, rir=rir, rir_handle=handle,
        signal_type="person_evidence", anchor_kind="person", via_entity_id=root.id, evidence_id=ev.id,
        quote=f"net {ipaddress.ip_network(value).network_address}",
    ).candidate
    w.db.commit()
    return c


def test_an_excluded_child_that_is_an_existing_ripe_candidate_gets_one_context_signal(w, t):
    root, claimed = _setup(w, t)
    child = _existing(w, root, S25[1], "ripe", "ORG-CHILD1")
    ex = arin.ExcludedChild("CHILD-1", "org", "ORG-CHILD1", (S25[1],))
    r = ripe.record_ripe(w.db, claimed=claimed, collection=_one_net_coll(claimed, pieces=(S25[0],), excluded=(ex,)))
    w.db.commit()
    assert r.signals_recorded == 1 and (r.context_recorded, r.context_no_candidate) == (1, 0)
    assert _types(w.db, child) == ["person_evidence", "rir_reassigned_elsewhere"]
    assert (child.rir, child.rir_handle) == ("ripe", "ORG-CHILD1")
    q = w.db.execute(select(ScopeSignal.quote).where(
        ScopeSignal.candidate_id == child.id, ScopeSignal.signal_type == "rir_reassigned_elsewhere")).scalar_one()
    assert q == f"{S25[1]} is inside RIPE inetnum {irange(A24)} held by org ORG-TEST1 but is registered to org ORG-CHILD1"
    # a re-run re-sights it: still one
    again = ripe.record_ripe(w.db, claimed=claimed, collection=_one_net_coll(claimed, pieces=(S25[0],), excluded=(ex,)))
    w.db.commit()
    assert again.context_recorded == 1
    assert _types(w.db, child) == ["person_evidence", "rir_reassigned_elsewhere"]


def test_the_same_excluded_prefix_listed_twice_is_one_context_signal(w, t):
    root, claimed = _setup(w, t)
    _existing(w, root, S25[1], "ripe", "ORG-CHILD1")
    ex = arin.ExcludedChild("CHILD-1", "org", "ORG-CHILD1", (S25[1],))
    r = ripe.record_ripe(w.db, claimed=claimed, collection=_one_net_coll(claimed, pieces=(S25[0],), excluded=(ex, ex)))
    w.db.commit()
    assert r.context_recorded == 1


def test_an_excluded_child_held_as_an_arin_candidate_gets_no_context_signal(w, t):
    root, claimed = _setup(w, t)
    child = _existing(w, root, S25[1], "arin", "NET-CHILD")
    ex = arin.ExcludedChild("CHILD-1", "org", "ORG-CHILD1", (S25[1],))
    r = ripe.record_ripe(w.db, claimed=claimed, collection=_one_net_coll(claimed, pieces=(S25[0],), excluded=(ex,)))
    w.db.commit()
    assert r.signals_recorded == 1  # the path was reached
    assert (r.context_recorded, r.context_no_candidate) == (0, 1)
    assert _types(w.db, child) == ["person_evidence"]


def test_an_excluded_child_that_is_not_a_candidate_is_counted_and_creates_nothing(w, t):
    root, claimed = _setup(w, t)
    ex = arin.ExcludedChild("CHILD-1", "unknown", None, (S25[1],))
    r = ripe.record_ripe(w.db, claimed=claimed, collection=_one_net_coll(claimed, pieces=(S25[0],), excluded=(ex,)))
    w.db.commit()
    assert r.signals_recorded == 1
    assert (r.context_recorded, r.context_no_candidate) == (0, 1)
    assert _cand(w.db, root.id, S25[1], "cidr") is None


def test_context_is_also_recorded_for_a_failed_resources_excluded_children(w, t):
    root, claimed = _setup(w, t)
    child = _existing(w, root, S25[1], "ripe", "ORG-CHILD1")
    ex = arin.ExcludedChild("CHILD-1", "org", "ORG-CHILD1", (S25[1],))
    r = ripe.record_ripe(w.db, claimed=claimed, collection=_one_net_coll(claimed, pieces=(), excluded=(ex,), failed="too_many_pieces"))
    w.db.commit()
    assert r.signals_recorded == 0 and r.context_recorded == 1
    assert _types(w.db, child) == ["person_evidence", "rir_reassigned_elsewhere"]


# ── no Strong path ───────────────────────────────────────────────────────────


def test_no_ripe_path_can_write_a_strong_signal():
    src = inspect.getsource(ripe)
    literals = set()
    calls = 0
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "record_signal":
            calls += 1
            kw = {k.arg: k.value for k in node.keywords}
            assert isinstance(kw.get("signal_type"), ast.Constant), "signal_type must be a literal"
            literals.add(kw["signal_type"].value)
    assert calls == 2  # the AST walk found the call sites at all
    assert literals == {"rir_contact_email_unvalidated", "rir_reassigned_elsewhere"}
    assert "rir_contact_email_claimed" not in src


# ── runner ───────────────────────────────────────────────────────────────────


def _empty_arin(db, domain, fresh_since=None):
    return arin.ArinCollection(domain=domain, pocs_listed=0, pocs_truncated=False, pocs_not_exact=0, matched=())


def _arin_coll(domain, t):
    org = f"{t}-AORG"
    return arin.ArinCollection(
        domain=domain, pocs_listed=1, pocs_truncated=False, pocs_not_exact=0,
        matched=(arin.MatchedPoc(f"{t}-P1", True, ("example.com",), ((org, ("AD",)),)),),
        orgs={org: arin.OrgResult(handle=org, asns=("AS64501",), nets=(), asns_truncated=False, nets_truncated=False,
                                  skipped_nested=0, skipped_not_held=0, skipped_type=0, invalid=0)},
    )


def _ripe_coll(domain):
    return _coll(domain, [_contact("RL1-TEST", domain)], [_r("aut-num", "AS64500", asn="AS64500", status="ASSIGNED")])


def _fresh(root_id):
    db = SessionLocal()
    try:
        return sorted(
            (c.kind, c.value, c.rir) for c in db.execute(
                select(ScopeCandidate).where(ScopeCandidate.root_entity_id == root_id, ScopeCandidate.kind != "domain")
            ).scalars()
        )
    finally:
        db.close()


def test_both_registries_run_and_each_records(w, t, monkeypatch):
    root, claimed = _setup(w, t)
    monkeypatch.setattr(runner, "_rir_collect", lambda db, d, fresh_since=None: _arin_coll(d, t))
    monkeypatch.setattr(runner, "_ripe_collect", lambda db, d, fresh_since=None: _ripe_coll(d))
    out = runner.rir_for_claimed(claimed.id)
    assert out.arin.signals_recorded == 1 and out.ripe.signals_recorded == 1
    assert _fresh(root.id) == [("asn", "AS64500", "ripe"), ("asn", "AS64501", "arin")]


def test_an_arin_failure_does_not_stop_ripe(w, t, monkeypatch):
    root, claimed = _setup(w, t)

    def boom(db, d, fresh_since=None):
        raise RuntimeError("arin down")

    monkeypatch.setattr(runner, "_rir_collect", boom)
    monkeypatch.setattr(runner, "_ripe_collect", lambda db, d, fresh_since=None: _ripe_coll(d))
    out = runner.rir_for_claimed(claimed.id)
    assert out.arin == arin.ArinRecordResult() and out.ripe.signals_recorded == 1
    assert _fresh(root.id) == [("asn", "AS64500", "ripe")]


def test_a_ripe_failure_does_not_undo_arin(w, t, monkeypatch):
    root, claimed = _setup(w, t)

    def boom(db, d, fresh_since=None):
        raise RuntimeError("ripe down")

    monkeypatch.setattr(runner, "_rir_collect", lambda db, d, fresh_since=None: _arin_coll(d, t))
    monkeypatch.setattr(runner, "_ripe_collect", boom)
    out = runner.rir_for_claimed(claimed.id)
    assert out.ripe == ripe.RipeRecordResult() and out.arin.signals_recorded == 1
    assert _fresh(root.id) == [("asn", "AS64501", "arin")]


def test_a_ripe_record_failure_rolls_back_but_keeps_the_arin_signals(w, t, monkeypatch):
    root, claimed = _setup(w, t)

    def boom(*a, **k):
        raise RuntimeError("record exploded")

    monkeypatch.setattr(runner, "_rir_collect", lambda db, d, fresh_since=None: _arin_coll(d, t))
    monkeypatch.setattr(runner, "_ripe_collect", lambda db, d, fresh_since=None: _ripe_coll(d))
    monkeypatch.setattr(ripe, "record_ripe", boom)
    out = runner.rir_for_claimed(claimed.id)
    assert out.ripe == ripe.RipeRecordResult() and out.arin.signals_recorded == 1
    assert _fresh(root.id) == [("asn", "AS64501", "arin")]


def test_both_seams_empty_gives_the_empty_run_result(w, t, monkeypatch):
    root, claimed = _setup(w, t)
    reached = []
    monkeypatch.setattr(runner, "_rir_collect", lambda db, d, fresh_since=None: reached.append("arin") or _empty_arin(db, d))
    monkeypatch.setattr(runner, "_ripe_collect", lambda db, d, fresh_since=None: reached.append("ripe") or _coll(d, [], []))
    assert runner.rir_for_claimed(claimed.id) == runner.RirRunResult(arin.ArinRecordResult(), ripe.RipeRecordResult())
    assert reached == ["arin", "ripe"]  # both seams were reached


def test_an_unclaimed_or_missing_candidate_reaches_neither_seam(w, t, monkeypatch):
    root = w.ours()
    open_c = w.candidate(root, value=_dom(t))
    seen = []
    monkeypatch.setattr(runner, "_rir_collect", lambda db, d, fresh_since=None: seen.append("arin") or _empty_arin(db, d))
    monkeypatch.setattr(runner, "_ripe_collect", lambda db, d, fresh_since=None: seen.append("ripe") or _coll(d, [], []))
    empty = runner.RirRunResult()
    assert runner.rir_for_claimed(open_c.id) == empty
    assert runner.rir_for_claimed(uuid.uuid4()) == empty
    assert seen == []
    claimed = _claimed(w, root, _dom(t + "Y"))
    runner.rir_for_claimed(claimed.id)  # control: a claimed one reaches both
    assert seen == ["arin", "ripe"]


def test_the_conftest_stub_keeps_ripe_offline_by_default(w, t, monkeypatch):
    # No seam patched here: the autouse stub must answer, and the transport must never be touched.
    touched = []
    monkeypatch.setattr(rf, "connector_get", lambda *a, **k: touched.append(a) or None)
    root, claimed = _setup(w, t)
    assert runner.rir_for_claimed(claimed.id) == runner.RirRunResult()
    assert touched == []  # (a raise inside the runner would be swallowed, so record the touch instead)


# ── end to end ───────────────────────────────────────────────────────────────


def test_end_to_end_through_the_real_collector_and_wire_shapes(w, t, monkeypatch, cache_clean):
    router = Router()
    monkeypatch.setattr(rf, "connector_get", router)
    monkeypatch.setattr(runner, "_ripe_collect", lambda db, d, fresh_since=None: ripe.collect(db, d, rf.Budget(fresh_since=fresh_since)))
    root, claimed = _setup(w, t)
    dom = claimed.value
    org, org2, rl = "ORG-E2E1-TEST", "ORG-E2E2-TEST", "RL-E2E-TEST"
    router.ft([ft_doc(rl, "role", [f"noc@{dom}"])])
    router.inv(rl, [organisation(org)])
    router.inv(org, [net4(A24, org=org)], kind="org")
    router.om(irange(A24), [net4(A24, org=org), net4(S25[1], org=org2)])
    out = runner.rir_for_claimed(claimed.id)
    assert router.calls  # the transport was reached
    assert out.ripe.signals_recorded == 1 and out.arin == arin.ArinRecordResult()
    assert _fresh(root.id) == [("cidr", S25[0], "ripe")]
    db = SessionLocal()
    try:
        c = db.execute(select(ScopeCandidate).where(ScopeCandidate.root_entity_id == root.id, ScopeCandidate.value == S25[0])).scalar_one()
        assert c.rir_handle == org
        sig = db.execute(select(ScopeSignal).where(ScopeSignal.candidate_id == c.id)).scalar_one()
        assert sig.signal_type == "rir_contact_email_unvalidated" and sig.matched_values == [dom]
        body = json.loads(db.get(EvidenceBlob, db.get(EvidenceFetch, sig.evidence_id).sha256).content)
        assert body["excluded"] == [{"handle": irange(S25[1]),
                                     "holder_kind": "org", "holder_handle": org2, "prefixes": [S25[1]]}]
        assert body["via"][0]["handle"] == rl and body["holder"] == org
        assert "@" not in json.dumps(body)
    finally:
        db.close()
