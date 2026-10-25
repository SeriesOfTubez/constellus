"""Read-only backend for the Organizations page (planning#277 S2a): the affiliate
tree, the detail summary, candidate-list extensions, per-target asset and
finding rollups, the signal catalogue and the effective permissions on
`/auth/me`.

Synthetic names only. Run with:  scripts/test.sh app/tests/test_organizations_s2_api.py
"""

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import false, true

from app.models.asset_canonical import AssetCanonical
from app.models.finding_canonical import FindingCanonical
from app.models.target_asset_link import TargetAssetLink
from app.models.user import UserRole
from app.services import read_scope
from app.services.org_discovery import candidates as cd
from app.services.org_discovery.tiers import SIGNALS
from app.tests._org_world import World, client
from app.tests.test_org_discovery_schema import _insert_candidate, _insert_signal

VIEWER = UserRole.VIEWER.value


@pytest.fixture
def w():
    world = World()
    world.assets = []
    try:
        yield world
    finally:
        if world.assets:
            world.db.rollback()
            world.db.query(AssetCanonical).filter(AssetCanonical.id.in_(world.assets)).delete(synchronize_session=False)
            world.db.commit()
        world.close()


def _tree(w, root, headers=None, **kw):
    return client.get(f"/api/organizations/{root.id}/tree", headers=headers or w.headers(role=VIEWER), **kw)


def _by_id(r):
    assert r.status_code == 200, r.text
    return {n["entity_id"]: n for n in r.json()}


# ── tree ────────────────────────────────────────────────────────────────────


def test_tree_has_subsidiary_and_acquired_children_with_depth(w):
    root = w.ours()
    sub = w.child_of(root)
    grand = w.child_of(sub)
    bought = w.entity()
    w.edge(root, bought, "acquired")
    nodes = _by_id(_tree(w, root))
    assert len(nodes) == 4
    r = nodes[str(root.id)]
    assert (r["parent_id"], r["relation"], r["depth"], r["status"], r["name"]) == (None, None, 0, "confirmed", root.legal_name)
    assert (nodes[str(sub.id)]["parent_id"], nodes[str(sub.id)]["relation"], nodes[str(sub.id)]["depth"]) == (str(root.id), "subsidiary_of", 1)
    assert (nodes[str(grand.id)]["parent_id"], nodes[str(grand.id)]["depth"]) == (str(sub.id), 2)
    assert (nodes[str(bought.id)]["relation"], nodes[str(bought.id)]["parent_id"]) == ("acquired", str(root.id))
    assert nodes[str(bought.id)]["event_date"] is None


def test_tree_excludes_a_child_that_is_its_own_root_and_what_hangs_under_it(w):
    root = w.ours()
    plain = w.child_of(root)
    other_root = w.child_of(root)
    w.ours(other_root)  # precondition for the exclusion: it now has a relationship
    assert w.db.get(type(other_root), other_root.id).relationship == "ours"
    under_other = w.child_of(other_root)
    nodes = _by_id(_tree(w, root))
    assert str(plain.id) in nodes
    assert str(other_root.id) not in nodes and str(under_other.id) not in nodes


def test_tree_terminates_on_a_cycle(w):
    root = w.ours()
    a = w.child_of(root)
    b = w.child_of(a)
    w.edge(a, b, "subsidiary_of")  # a is b's subsidiary too: a -> b -> a
    w.edge(root, a, "subsidiary_of")  # and root hangs under a: back to the root
    r_nodes = _tree(w, root).json()
    assert sorted(n["entity_id"] for n in r_nodes) == sorted(str(e.id) for e in (root, a, b))  # each exactly once


def test_tree_shows_a_proposed_edge_once_and_never_walks_it(w):
    root = w.ours()
    confirmed = w.child_of(root)
    prop = w.entity()
    w.edge(prop, root, "subsidiary_of", confirm=False)
    under_prop = w.child_of(prop)  # a confirmed edge beneath the proposed node
    nodes = _by_id(_tree(w, root))
    assert nodes[str(prop.id)]["status"] == "proposed"
    assert nodes[str(prop.id)]["parent_id"] == str(root.id)
    assert nodes[str(confirmed.id)]["status"] == "confirmed"
    assert str(under_prop.id) not in nodes  # not walked
    # a proposed edge hanging off a confirmed node is shown one hop out
    deeper = w.entity()
    w.edge(deeper, confirmed, "subsidiary_of", confirm=False)
    nodes = _by_id(_tree(w, root))
    assert nodes[str(deeper.id)]["status"] == "proposed" and nodes[str(deeper.id)]["parent_id"] == str(confirmed.id)
    assert nodes[str(deeper.id)]["depth"] == 2


def test_tree_never_shows_a_rejected_edge(w):
    root = w.ours()
    rejected = w.entity()
    rel = w.edge(rejected, root, "subsidiary_of", confirm=False)
    from app.services import entity_graph

    entity_graph.decide(w.db, relation_id=rel.id, status="rejected", user=w.user())
    kept = w.child_of(root)
    nodes = _by_id(_tree(w, root))
    assert str(kept.id) in nodes  # the walk ran
    assert str(rejected.id) not in nodes


def test_tree_drops_a_hidden_entity_with_its_subtree_and_404s_a_hidden_root(w, monkeypatch):
    root = w.ours()
    hidden = w.child_of(root)
    below = w.child_of(hidden)
    shown = w.child_of(root)
    h = w.headers(role=VIEWER)
    assert {str(hidden.id), str(below.id)} <= set(_by_id(_tree(w, root, h)))  # visible before
    monkeypatch.setattr(read_scope, "entity_clause", lambda user, entity: entity.id != hidden.id)
    nodes = _by_id(_tree(w, root, h))
    assert str(shown.id) in nodes
    assert str(hidden.id) not in nodes and str(below.id) not in nodes
    monkeypatch.setattr(read_scope, "entity_clause", lambda user, entity: entity.id != root.id)
    assert _tree(w, root, h).status_code == 404


def test_tree_hides_an_edge_the_relation_clause_hides(w, monkeypatch):
    root = w.ours()
    a = w.child_of(root)
    monkeypatch.setattr(read_scope, "relation_clause", lambda user, rel: rel.subject_id != a.id)
    assert set(_by_id(_tree(w, root))) == {str(root.id)}


def test_tree_404s_for_unknown_and_non_root(w):
    h = w.headers(role=VIEWER)
    assert client.get(f"/api/organizations/{uuid.uuid4()}/tree", headers=h).status_code == 404
    assert client.get(f"/api/organizations/{w.entity().id}/tree", headers=h).status_code == 404


# ── fixtures for candidates ─────────────────────────────────────────────────


def _mixed(w):
    """root -> childA -> grand, root -> sibling; candidates in every bucket."""
    root = w.ours()
    child = w.child_of(root)
    grand = w.child_of(child)
    sibling = w.child_of(root)
    ids = {}
    ids["strong"] = w.candidate(root, via=grand, value="a-strong.example.com").id
    ids["supp"] = _insert_candidate(w.db, root.id, value="b-supp.example.com")
    for t in ("mx_into_claimed", "shared_vanity_ns"):
        _insert_signal(w.db, ids["supp"], sibling.id, signal_type=t, evidence_id=w.evidence_row().id, quote="q")
    ids["lead"] = _insert_candidate(w.db, root.id, value="c-lead.example.com")
    _insert_signal(w.db, ids["lead"], child.id, signal_type="research_quote", evidence_id=w.evidence_row().id, quote="q")
    ids["lead2"] = _insert_candidate(w.db, root.id, value="d-ctx.example.com")  # context only: still a lead by the shared rule
    _insert_signal(w.db, ids["lead2"], root.id, signal_type="name_similarity", evidence_id=w.evidence_row().id, quote="q")
    ids["bare"] = _insert_candidate(w.db, root.id, value="e-bare.example.com")  # no signal: not a lead
    ids["claimed"] = w.candidate(root, value="f-claimed.example.com").id
    claimed = cd.claim(w.db, candidate_id=ids["claimed"], user=w.user())
    w.track_target(claimed.target.value)
    ids["rejected"] = w.candidate(root, value="g-rejected.example.com").id
    cd.reject(w.db, candidate_id=ids["rejected"], user=w.user(), reason="a vendor")
    return root, child, grand, sibling, ids


def _list(w, root, qs="", headers=None):
    r = client.get(f"/api/organizations/{root.id}/candidates?{qs}", headers=headers or w.headers(role=VIEWER))
    return r


def _values(r):
    assert r.status_code == 200, r.text
    return [x["value"] for x in r.json()["items"]]


def _summary(w, root, qs=""):
    r = client.get(f"/api/organizations/{root.id}/summary?{qs}", headers=w.headers(role=VIEWER))
    assert r.status_code == 200, r.text
    return r.json()


# ── subtree filter ──────────────────────────────────────────────────────────


def test_subtree_filter_includes_a_grandchilds_candidate_under_the_child_not_under_a_sibling(w):
    root, child, grand, sibling, ids = _mixed(w)
    assert {"a-strong.example.com"} <= set(_values(_list(w, root, f"subtree_of={child.id}")))   # via grand, under child
    assert {"a-strong.example.com"} <= set(_values(_list(w, root, f"subtree_of={grand.id}")))
    sib = set(_values(_list(w, root, f"subtree_of={sibling.id}")))
    assert not {"a-strong.example.com"} & sib and {"b-supp.example.com"} <= sib  # the sibling's own is there
    # the same on the summary
    assert _summary(w, root, f"subtree_of={child.id}")["to_review"] == 1       # strong only
    assert _summary(w, root, f"subtree_of={sibling.id}")["to_review"] == 1     # supp only
    assert _summary(w, root, f"subtree_of={root.id}")["to_review"] == 2
    assert _summary(w, root, f"subtree_of={child.id}")["leads"] == 1           # c-lead via child


def test_subtree_of_a_proposed_node_or_another_roots_node_is_404(w):
    root, child, _g, _s, _ids = _mixed(w)
    prop = w.entity()
    w.edge(prop, root, "subsidiary_of", confirm=False)
    elsewhere = w.child_of(w.ours())
    for node in (prop, elsewhere, w.entity()):
        assert _list(w, root, f"subtree_of={node.id}").status_code == 404
        assert client.get(f"/api/organizations/{root.id}/summary?subtree_of={node.id}",
                          headers=w.headers(role=VIEWER)).status_code == 404


# ── leads / summary ─────────────────────────────────────────────────────────


def test_leads_only_matches_the_summary_for_every_bucket(w):
    root, *_rest, ids = _mixed(w)
    s = _summary(w, root)
    # every bucket the fixture claims to hold is non-empty (the precondition fired)
    assert s["claimed"] == 1 and s["to_review"] == 2 and s["leads"] == 2 and s["rejected"] == 1
    vals = _values(_list(w, root, "leads_only=true"))
    assert len(vals) == s["leads"] and set(vals) == {"c-lead.example.com", "d-ctx.example.com"}
    # status / include_leads do not narrow it
    assert _values(_list(w, root, "leads_only=true&status=claimed")) == vals
    assert _list(w, root, "leads_only=true").json()["total"] == s["leads"]
    # and under a subtree
    sub = _values(_list(w, root, f"leads_only=true&subtree_of={_rest[0].id}"))
    assert len(sub) == _summary(w, root, f"subtree_of={_rest[0].id}")["leads"] == 1


def test_summary_fields(w):
    root = w.ours()
    a = w.child_of(root)
    w.child_of(a)
    prop = w.entity()
    w.edge(prop, root, "subsidiary_of", confirm=False)
    s = _summary(w, root)
    assert (s["affiliates"], s["proposed_affiliates"], s["has_filer"]) == (2, 1, False)
    assert s["assets_under_claimed_scope"] == 0 and set(s) == {
        "claimed", "to_review", "leads", "rejected", "assets_under_claimed_scope", "has_filer", "affiliates",
        "proposed_affiliates",
    }
    root.cik = "0000000001"
    w.db.commit()
    s = _summary(w, root)
    assert s["has_filer"] is True and "0000000001" not in str(s)


def test_summary_404s_for_non_root_and_hidden_root(w, monkeypatch):
    h = w.headers(role=VIEWER)
    assert client.get(f"/api/organizations/{w.entity().id}/summary", headers=h).status_code == 404
    root = w.ours()
    monkeypatch.setattr(read_scope, "entity_clause", lambda user, entity: entity.id != root.id)
    assert client.get(f"/api/organizations/{root.id}/summary", headers=h).status_code == 404


def test_summary_applies_the_domain_clause(w, monkeypatch):
    root, *_rest, ids = _mixed(w)
    hidden = {ids["strong"], ids["lead"]}
    monkeypatch.setattr(read_scope, "domain_clause", lambda user, d: d.id.notin_(hidden))
    s = _summary(w, root)
    assert (s["to_review"], s["leads"]) == (1, 1)


# ── list extensions ─────────────────────────────────────────────────────────


def test_q_is_a_literal_substring_and_percent_does_not_match_everything(w):
    root, *_r, ids = _mixed(w)
    all_vals = _values(_list(w, root, "status=all&include_leads=true"))
    assert len(all_vals) >= 6
    assert _values(_list(w, root, "status=all&include_leads=true&q=%25")) == []
    assert _values(_list(w, root, "status=all&include_leads=true&q=_")) == []
    assert _values(_list(w, root, "status=all&include_leads=true&q=A-STRONG")) == ["a-strong.example.com"]
    assert _list(w, root, "q=" + "a" * 254).status_code == 422


def test_signal_type_filter_and_422_on_unknown(w):
    root, *_r, ids = _mixed(w)
    qs = "status=all&include_leads=true&signal_type="
    assert _values(_list(w, root, qs + "mx_into_claimed")) == ["b-supp.example.com"]
    assert _values(_list(w, root, qs + "research_quote")) == ["c-lead.example.com"]
    assert set(_values(_list(w, root, qs + "person_evidence"))) >= {"a-strong.example.com"}
    assert _list(w, root, qs + "not_a_signal").status_code == 422


def test_total_is_the_filtered_count_before_limit_and_offset(w):
    root, *_r = _mixed(w)
    r = _list(w, root, "status=all&include_leads=true&limit=2").json()
    assert len(r["items"]) == 2 and r["total"] == 7 and r["total"] != len(r["items"])
    r2 = _list(w, root, "status=all&include_leads=true&limit=2&offset=6").json()
    assert len(r2["items"]) == 1 and r2["total"] == 7


# ── asset / finding counts ──────────────────────────────────────────────────


def _asset(w, value, *targets):
    now = datetime.now(timezone.utc)
    a = AssetCanonical(id=uuid.uuid4(), asset_type="dns_record", value=value, tags=[], first_seen_at=now,
                       last_seen_at=now, ignored=False)
    w.db.add(a)
    w.db.flush()
    w.assets.append(a.id)
    for t in targets:
        w.db.add(TargetAssetLink(target_id=t, asset_canonical_id=a.id, first_linked_at=now, last_observed_at=now))
    w.db.commit()
    return a.id


def _finding(w, asset_id, severity, state="open", verification=None):
    now = datetime.now(timezone.utc)
    w.db.add(FindingCanonical(
        id=uuid.uuid4(), asset_canonical_id=asset_id, finding_type="cve", source="test",
        fingerprint=f"s2-{uuid.uuid4().hex[:10]}", severity=severity, title="synthetic", state=state,
        verification=verification, first_seen_at=now, last_seen_at=now, detail={}, tags=[],
    ))
    w.db.commit()


def _counted_world(w):
    root, *_r, ids = _mixed(w)
    from app.models.scope_candidate import ScopeCandidate

    cand = w.db.get(ScopeCandidate, ids["claimed"])
    t = cand.target_id
    a1 = _asset(w, "www.fabrikam.com", t)
    a2 = _asset(w, "api.fabrikam.com", t)
    _asset(w, "unlinked.contoso.example")  # linked to nothing: never counted
    _finding(w, a1, "critical")
    _finding(w, a1, "low", state="acknowledged")       # acknowledged is open
    _finding(w, a2, "high")
    _finding(w, a2, "high", state="resolved")           # closed: not counted
    _finding(w, a2, "high", verification="rejected_shared_infra")  # excluded by the verifier
    _finding(w, a2, "info")                              # unmapped -> unknown
    return root, ids


def _claimed_row(w, root):
    items = _list(w, root, "status=claimed", w.headers()).json()["items"]
    assert len(items) == 1
    return items[0]


def test_claimed_row_counts_assets_findings_and_worst(w):
    root, ids = _counted_world(w)
    row = _claimed_row(w, root)
    assert row["asset_count"] == 2
    assert row["open_findings"] == {"critical": 1, "high": 1, "medium": 0, "low": 1, "unknown": 1}
    assert row["worst_severity"] == "critical"
    detail = client.get(f"/api/organizations/candidates/{ids['claimed']}", headers=w.headers()).json()
    assert (detail["asset_count"], detail["worst_severity"]) == (2, "critical")
    assert detail["open_findings"] == row["open_findings"]
    assert _summary(w, root)["assets_under_claimed_scope"] == 2


def test_open_and_rejected_candidates_get_nulls(w):
    root, ids = _counted_world(w)
    from app.models.scope_candidate import ScopeCandidate

    # Even if a non-claimed row somehow carries the claimed row's target, it gets no rollup.
    target = w.db.get(ScopeCandidate, ids["claimed"]).target_id
    for key in ("rejected", "lead", "strong"):
        w.db.get(ScopeCandidate, ids[key]).target_id = target
    w.db.commit()
    assert _claimed_row(w, root)["asset_count"] == 2  # the target does have assets
    for qs in ("include_leads=true", "status=rejected"):
        items = _list(w, root, qs, w.headers()).json()["items"]
        assert items  # the precondition: rows of those statuses exist
        for it in items:
            assert (it["asset_count"], it["open_findings"], it["worst_severity"]) == (None, None, None)


def test_a_claimed_row_with_no_assets_gets_zeros_not_nulls(w):
    root, *_r = _mixed(w)
    row = _claimed_row(w, root)
    assert row["target_id"] is not None
    assert (row["asset_count"], row["worst_severity"]) == (0, None)
    assert row["open_findings"] == {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}


def test_a_hidden_asset_is_not_counted_but_its_findings_follow_finding_clause(w, monkeypatch):
    root, ids = _counted_world(w)
    a_hidden = w.db.query(AssetCanonical).filter_by(value="api.fabrikam.com").one().id
    monkeypatch.setattr(read_scope, "asset_clause", lambda user, asset: asset.id != a_hidden)
    row = _claimed_row(w, root)
    assert row["asset_count"] == 1
    assert row["open_findings"]["high"] == 1  # finding_clause is the findings' own gate
    assert _summary(w, root)["assets_under_claimed_scope"] == 1
    monkeypatch.setattr(read_scope, "asset_clause", lambda user, asset: true())
    monkeypatch.setattr(read_scope, "finding_clause", lambda user, f, asset: asset.id != a_hidden)
    row = _claimed_row(w, root)
    assert row["asset_count"] == 2
    assert row["open_findings"] == {"critical": 1, "high": 0, "medium": 0, "low": 1, "unknown": 0}


def test_summary_assets_follow_the_subtree_filter(w):
    root, ids = _counted_world(w)
    child = w.child_of(root)
    assert _summary(w, root, f"subtree_of={child.id}")["assets_under_claimed_scope"] == 0
    assert _summary(w, root, f"subtree_of={root.id}")["assets_under_claimed_scope"] == 2


# ── /auth/me ────────────────────────────────────────────────────────────────


def _me(w, role):
    r = client.get("/api/auth/me", headers=w.headers(role=role))
    assert r.status_code == 200, r.text
    return r.json()


def test_me_lists_effective_permissions_per_role(w):
    admin = _me(w, UserRole.ADMIN.value)["permissions"]
    assert "entities.decide_candidate" in admin and "organizations.create" in admin
    assert admin == sorted(admin)
    ia = _me(w, UserRole.INTEGRATION_ADMIN.value)["permissions"]
    assert "connectors.configure" in ia and "entities.decide_candidate" not in ia
    viewer = _me(w, VIEWER)["permissions"]
    assert "entities.read" in viewer  # the list is not simply empty
    assert "entities.decide_candidate" not in viewer and "connectors.configure" not in viewer


def test_another_user_endpoint_does_not_expose_permissions(w):
    r = client.get("/api/users/", headers=w.headers())
    assert r.status_code == 200 and r.json()
    assert all("permissions" not in u for u in r.json())


# ── signal catalogue ────────────────────────────────────────────────────────


def test_signal_types_lists_every_signal_once_with_a_label(w):
    r = client.get("/api/organizations/signal-types", headers=w.headers(role=VIEWER))
    assert r.status_code == 200, r.text
    rows = r.json()
    assert sorted(x["signal_type"] for x in rows) == sorted(SIGNALS)
    for x in rows:
        spec = SIGNALS[x["signal_type"]]
        assert (x["tier"], x["family"], x["built"], x["description"]) == (spec.tier, spec.family, spec.built, spec.description)
        assert x["label"].strip()


def test_every_signals_entry_has_a_label():
    assert all(spec.label.strip() for spec in SIGNALS.values())


def test_candidate_list_404s_for_unknown_non_root_and_hidden_root(w, monkeypatch):
    h = w.headers(role=VIEWER)
    assert client.get(f"/api/organizations/{uuid.uuid4()}/candidates", headers=h).status_code == 404
    assert client.get(f"/api/organizations/{w.entity().id}/candidates", headers=h).status_code == 404
    root = w.ours()
    assert client.get(f"/api/organizations/{root.id}/candidates", headers=h).status_code == 200
    monkeypatch.setattr(read_scope, "entity_clause", lambda user, entity: entity.id != root.id)
    assert client.get(f"/api/organizations/{root.id}/candidates", headers=h).status_code == 404


def test_signal_types_is_not_shadowed_by_the_org_id_routes(w):
    r = client.get("/api/organizations/signal-types", headers=w.headers(role=VIEWER))
    assert r.status_code == 200 and isinstance(r.json(), list)  # not a 422 from a UUID path param


# ── locate ──────────────────────────────────────────────────────────────────


def _locate(w, entity_id, headers=None):
    return client.get(f"/api/organizations/locate/{entity_id}", headers=headers or w.headers(role=VIEWER))


def test_locate_a_root_is_itself_with_no_node(w):
    root = w.ours()
    r = _locate(w, root.id)
    assert r.status_code == 200, r.text
    assert r.json() == {"org_id": str(root.id), "node": None}


def test_locate_a_confirmed_subsidiary_two_hops_down(w):
    root = w.ours()
    sub = w.child_of(w.child_of(root))
    r = _locate(w, sub.id)
    assert r.status_code == 200, r.text
    assert r.json() == {"org_id": str(root.id), "node": str(sub.id)}


def test_locate_an_acquired_entity_goes_to_the_acquirer(w):
    root = w.ours()
    bought = w.entity()
    w.edge(root, bought, "acquired")
    r = _locate(w, bought.id)
    assert r.status_code == 200, r.text
    assert r.json() == {"org_id": str(root.id), "node": str(bought.id)}


def test_locate_404s_for_a_proposed_only_subsidiary(w):
    root = w.ours()
    w.child_of(root)  # the walk has something to find
    prop = w.entity()
    w.edge(prop, root, "subsidiary_of", confirm=False)
    assert _locate(w, prop.id).status_code == 404
    assert _locate(w, root.id).status_code == 200  # the route works for this root


def test_locate_404s_for_an_entity_with_no_path_to_a_root(w):
    w.ours()
    lone = w.entity()
    r = _locate(w, lone.id)
    assert r.status_code == 404
    assert r.json()["detail"] == "Not part of an organization you can see"


def test_locate_404s_under_a_root_the_caller_cannot_see_but_not_for_a_member(w, monkeypatch):
    root, _eng = w.deal()
    sub = w.child_of(root)
    member = w.headers(role=VIEWER)
    outsider_user = w.user(VIEWER)
    outsider = w.headers(user=outsider_user)
    # `entity_clause` grants everything today, so scope is simulated the way the tree tests do:
    # everything under the restricted root is hidden from the non-member only.
    hidden = {root.id, sub.id}
    monkeypatch.setattr(
        read_scope, "entity_clause",
        lambda user, entity: true() if user.id != outsider_user.id else entity.id.notin_(hidden),
    )
    ok = _locate(w, sub.id, member)
    assert ok.status_code == 200, ok.text
    assert ok.json() == {"org_id": str(root.id), "node": str(sub.id)}
    assert _locate(w, sub.id, outsider).status_code == 404
    # entity visible but its root hidden: still 404, via the root check rather than the entity load
    monkeypatch.setattr(
        read_scope, "entity_clause",
        lambda user, entity: true() if user.id != outsider_user.id else entity.id != root.id,
    )
    assert _locate(w, sub.id, member).status_code == 200
    assert _locate(w, sub.id, outsider).status_code == 404


def test_locate_404s_when_the_only_edge_to_the_root_is_hidden_by_relation_scope(w, monkeypatch):
    """`resolve()` walks edges without read scope; membership must come from the
    scoped tree, so an edge the caller cannot read never locates."""
    root = w.ours()
    sub = w.child_of(root)
    outsider_user = w.user(VIEWER)
    outsider = w.headers(user=outsider_user)
    monkeypatch.setattr(
        read_scope, "relation_clause",
        lambda user, rel: true() if user.id != outsider_user.id else false(),
    )
    ok = _locate(w, sub.id, w.headers(role=VIEWER))
    assert ok.status_code == 200, ok.text
    assert ok.json() == {"org_id": str(root.id), "node": str(sub.id)}
    assert _locate(w, sub.id, outsider).status_code == 404


def test_locate_a_nested_root_is_itself_not_its_parent_root(w):
    root = w.ours()
    nested = w.child_of(root)
    w.ours(nested)
    assert w.db.get(type(nested), nested.id).relationship == "ours"
    r = _locate(w, nested.id)
    assert r.status_code == 200, r.text
    assert r.json() == {"org_id": str(nested.id), "node": None}


def test_locate_404s_for_an_unknown_uuid(w):
    r = _locate(w, uuid.uuid4())
    assert r.status_code == 404
    assert r.json()["detail"] == "Entity not found"
