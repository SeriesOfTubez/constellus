"""GET /api/organizations/{org_id}/acquisitions and the pure rules in
`services/org_discovery/rollup.py` (planning#277 S4a).

Synthetic data only: random "Example Holdings" names, `*.example.com` domains,
RFC 3849 prefixes, RFC 5398 documentation ASNs. The World removes everything it
made; assets (and, by cascade, their links and findings) are removed here.

Run with:  scripts/test.sh app/tests/test_organizations_acquisitions_api.py
"""

import uuid
from datetime import date, datetime, timedelta, timezone

import pytest
from sqlalchemy import false, text

from app.models.asset_canonical import AssetCanonical
from app.models.engagement import Engagement
from app.models.entity_relation import EntityRelation
from app.models.finding_canonical import FindingCanonical
from app.models.scope_candidate import ScopeCandidate
from app.models.target import Target
from app.models.target_asset_link import TargetAssetLink
from app.models.user import UserRole
from app.services import org_tree, read_scope
from app.services.org_discovery import candidates as cd
from app.services.org_discovery import rollup
from app.services.org_discovery.reassignment import Reassigned, record_reassignment
from app.tests._org_world import World, client

# Reused fixtures: the cloud-ranges meta row a CIDR or ASN claim needs.
from app.tests.test_org_discovery_asn_cidr import _asn_cand, _cidr, meta  # noqa: F401

VIEWER = UserRole.VIEWER.value
NOW = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def w():
    world = World()
    world.assets = []
    try:
        yield world
    finally:
        world.db.rollback()
        if world.assets:
            world.db.query(AssetCanonical).filter(AssetCanonical.id.in_(world.assets)).delete(synchronize_session=False)
            world.db.commit()
        world.close()


# ── helpers ─────────────────────────────────────────────────────────────────


def _acquired(w, parent, closed=None, precision="unknown", confirm=True):
    """A new company `parent` acquired; `closed` sets the relation's event date."""
    company = w.entity()
    rel = w.edge(parent, company, "acquired", confirm=confirm)
    if closed is not None:
        rel = w.db.get(EntityRelation, rel.id)
        rel.event_date, rel.event_date_precision = closed, precision
        w.db.commit()
    return company


def _claim(w, root, kind="domain", aff=None, n=0, asn="AS64500"):
    """A claimed candidate of `kind` under `root`, affiliated with `aff` (default: the root)."""
    cand = {"domain": lambda: w.candidate(root), "cidr": lambda: _cidr(w, root, n),
            "asn": lambda: _asn_cand(w, root, asn)}[kind]()
    result = cd.claim(w.db, candidate_id=cand.id, user=w.user(), affiliated_entity_id=aff.id if aff else None)
    if result.target is not None:
        w.track_target(result.target.value)
    for p in result.prefixes:
        w.track_target(p.target.value)
    w.db.refresh(cand)
    return cand


def _in_review(w, root, kind="domain", n=0):
    """An open, proposable candidate (still to review)."""
    return w.candidate(root) if kind == "domain" else _cidr(w, root, n)


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


def _finding(w, asset_id, severity="high", state="open", verification=None, kev=None, vulncheck_kev=None, risk=None):
    now = datetime.now(timezone.utc)
    w.db.add(FindingCanonical(
        id=uuid.uuid4(), asset_canonical_id=asset_id, finding_type="cve", source="test",
        fingerprint=f"s4a-{uuid.uuid4().hex[:10]}", severity=severity, title="synthetic", state=state,
        verification=verification, kev=kev, vulncheck_kev=vulncheck_kev, risk_score=risk,
        first_seen_at=now, last_seen_at=now, detail={}, tags=[],
    ))
    w.db.commit()


def _decided(w, cand, when):
    """Set `decided_at` explicitly (the guard trigger allows no other path, so go around it for one statement)."""
    w.db.execute(text("ALTER TABLE scope_candidates DISABLE TRIGGER USER"))
    try:
        w.db.execute(text("UPDATE scope_candidates SET decided_at = :t WHERE id = :i"), {"t": when, "i": cand.id})
    finally:
        w.db.execute(text("ALTER TABLE scope_candidates ENABLE TRIGGER USER"))
    w.db.commit()
    w.db.refresh(cand)


def _get(w, root, headers=None):
    return client.get(f"/api/organizations/{root.id}/acquisitions", headers=headers or w.headers(role=VIEWER))


def _body(w, root):
    r = _get(w, root)
    assert r.status_code == 200, r.text
    return r.json()


def _rows(body):
    return {r["entity_id"]: r for r in body["rows"]}


def _sid(e):
    return str(e.id)


# ── 1. rows, order, per-kind counts ─────────────────────────────────────────


def test_rows_are_ordered_and_count_each_kind(w):
    root = w.ours()
    old = _acquired(w, root, date(2024, 3, 1), "day")
    new = _acquired(w, root, date(2026, 1, 15), "month")
    undated = _acquired(w, root)
    _claim(w, root, "domain", aff=old)
    _claim(w, root, "cidr", aff=old, n=1)
    _claim(w, root, "asn", aff=old)
    _claim(w, root, "domain", aff=new)
    _claim(w, root, "domain")  # the root's own domain: organic
    body = _body(w, root)
    assert [r["entity_id"] for r in body["rows"]] == [_sid(new), _sid(old), _sid(undated), None]
    rows = _rows(body)
    o, n_, u, org = rows[_sid(old)], rows[_sid(new)], rows[_sid(undated)], rows[None]
    assert (o["name"], o["closed"], o["closed_precision"], o["organic"]) == (old.legal_name, "2024-03-01", "day", False)
    assert (n_["closed"], n_["closed_precision"]) == ("2026-01-15", "month")
    assert (o["domains_claimed"], o["cidrs_claimed"], o["asns_claimed"]) == (1, 1, 1)
    assert (n_["domains_claimed"], n_["cidrs_claimed"], n_["asns_claimed"]) == (1, 0, 0)
    assert u["closed"] is None and u["closed_precision"] == "unknown"
    assert (org["name"], org["organic"], org["closed"], org["closed_precision"]) == (root.legal_name, True, None, None)
    assert (org["domains_claimed"], org["cidrs_claimed"], org["asns_claimed"]) == (1, 0, 0)


def test_same_closed_date_orders_by_name(w):
    root = w.ours()
    a, b = _acquired(w, root, date(2025, 5, 5), "day"), _acquired(w, root, date(2025, 5, 5), "day")
    names = [r["name"] for r in _body(w, root)["rows"][:2]]
    assert names == sorted([a.legal_name, b.legal_name])


# ── 2. nearest acquired ancestor ────────────────────────────────────────────


def test_buckets_follow_the_nearest_acquired_ancestor(w):
    root = w.ours()
    a = _acquired(w, root, date(2025, 1, 1), "day")
    sub_a = w.child_of(a)
    sub_root = w.child_of(root)
    b = _acquired(w, a, date(2026, 1, 1), "day")  # acquired by an acquired company
    sub_b = w.child_of(b)
    proposed = _acquired(w, root, confirm=False)
    for aff in (a, sub_a, sub_root, b, sub_b, root):
        _claim(w, root, "domain", aff=aff)
    body = _body(w, root)
    rows = _rows(body)
    assert _sid(proposed) not in rows
    assert len(body["rows"]) == 3  # a, b, organic
    assert rows[_sid(a)]["domains_claimed"] == 2      # a, sub_a
    assert rows[_sid(b)]["domains_claimed"] == 2      # b, sub_b: B is its own row
    assert rows[None]["domains_claimed"] == 2         # sub_root, root


@pytest.mark.parametrize("status", ["proposed", "rejected"])
def test_an_affiliate_that_is_not_a_confirmed_node_counts_as_organic(w, status):
    root = w.ours()
    deal = _acquired(w, root, date(2025, 1, 1), "day")
    left = _acquired(w, root, date(2025, 2, 1), "day")
    _claim(w, root, "domain", aff=deal)
    _claim(w, root, "domain", aff=left)
    before = _rows(_body(w, root))
    assert before[_sid(left)]["domains_claimed"] == 1 and before[None]["domains_claimed"] == 0  # reached
    # The edge leaves the confirmed tree after the claim (a claim needs a confirmed path; a test
    # must go around the no-demotion trigger to make the tree change underneath it).
    w.db.execute(text("ALTER TABLE entity_relations DISABLE TRIGGER USER"))
    try:
        w.db.execute(
            text(
                "UPDATE entity_relations SET status = :s, decision_kind = :k, decided_at = :d "
                "WHERE object_id = :o AND relation = 'acquired'"
            ),
            {"s": status, "k": "person" if status == "rejected" else None,
             "d": NOW if status == "rejected" else None, "o": left.id},
        )
    finally:
        w.db.execute(text("ALTER TABLE entity_relations ENABLE TRIGGER USER"))
    w.db.commit()
    after = _rows(_body(w, root))
    assert _sid(left) not in after  # not a confirmed acquisition: no row
    assert after[None]["domains_claimed"] == 1  # its candidate fell back to organic
    assert after[_sid(deal)]["domains_claimed"] == 1


# ── 3. overlap ──────────────────────────────────────────────────────────────


def test_an_asset_under_a_deal_domain_and_a_root_cidr_counts_under_the_deal_only(w):
    root = w.ours()
    deal = _acquired(w, root, date(2025, 1, 1), "day")
    d = _claim(w, root, "domain", aff=deal)
    c = _claim(w, root, "cidr", n=2)
    shared = _asset(w, "shared.example.com", d.target_id, c.target_id)
    only_cidr = _asset(w, "198.51.100.7", c.target_id)
    _finding(w, shared, "high", risk=40)
    _finding(w, only_cidr, "low", risk=10)
    rows = _rows(_body(w, root))
    assert rows[_sid(deal)]["assets"] == 1 and rows[None]["assets"] == 1
    assert rows[_sid(deal)]["open_findings"]["high"] == 1 and rows[None]["open_findings"]["high"] == 0
    assert rows[None]["open_findings"]["low"] == 1


def test_kind_rank_beats_decided_at(w):
    """The cidr was decided EARLIER than the domain; the domain still wins on rank."""
    root = w.ours()
    deal = _acquired(w, root, date(2025, 1, 1), "day")
    d = _claim(w, root, "domain", aff=deal)
    c = _claim(w, root, "cidr", n=3)
    _decided(w, d, NOW)
    _decided(w, c, NOW - timedelta(days=30))
    _asset(w, "ranked.example.com", c.target_id, d.target_id)
    rows = _rows(_body(w, root))
    assert (rows[_sid(deal)]["assets"], rows[None]["assets"]) == (1, 0)


def test_two_domain_claims_on_one_asset_earliest_decided_at_wins(w):
    root = w.ours()
    first, second = _acquired(w, root, date(2025, 1, 1), "day"), _acquired(w, root, date(2025, 2, 1), "day")
    c1, c2 = _claim(w, root, "domain", aff=first), _claim(w, root, "domain", aff=second)
    asset = _asset(w, "both.example.com", c1.target_id, c2.target_id)
    _finding(w, asset, "critical", risk=90)
    for earlier, later, winner, loser in ((c1, c2, first, second), (c2, c1, second, first)):
        _decided(w, earlier, NOW - timedelta(days=5))
        _decided(w, later, NOW)
        rows = _rows(_body(w, root))
        assert rows[_sid(winner)]["assets"] == 1 and rows[_sid(winner)]["open_findings"]["critical"] == 1
        assert rows[_sid(loser)]["assets"] == 0 and rows[_sid(loser)]["open_findings"]["critical"] == 0


def test_assets_summed_over_rows_are_the_distinct_attributed_assets(w):
    root = w.ours()
    d1, d2 = _acquired(w, root, date(2025, 1, 1), "day"), _acquired(w, root, date(2025, 2, 1), "day")
    c1, c2, c3 = _claim(w, root, "domain", aff=d1), _claim(w, root, "domain", aff=d2), _claim(w, root, "cidr", n=4)
    _asset(w, "a1.example.com", c1.target_id)
    _asset(w, "a2.example.com", c1.target_id, c2.target_id)
    _asset(w, "a3.example.com", c2.target_id, c3.target_id)
    _asset(w, "a4.example.com", c3.target_id)
    _asset(w, "unlinked.example.com")
    body = _body(w, root)
    assert sum(r["assets"] for r in body["rows"]) == 4


# ── 4. findings ─────────────────────────────────────────────────────────────


def test_open_findings_severity_worst_and_kev(w):
    root = w.ours()
    deal = _acquired(w, root, date(2025, 1, 1), "day")
    d = _claim(w, root, "domain", aff=deal)
    a = _asset(w, "f.example.com", d.target_id)
    _finding(w, a, "critical", kev=True, risk=95)
    _finding(w, a, "high", state="acknowledged", vulncheck_kev=True, risk=70)  # vulncheck_kev alone: not kev
    _finding(w, a, "high", vulncheck_kev=True, kev=False)  # likewise
    _finding(w, a, "medium", kev=True, vulncheck_kev=True, risk=0)  # both: counts once
    _finding(w, a, "medium")
    _finding(w, a, "low", kev=False)
    _finding(w, a, "info")  # unmapped -> unknown
    _finding(w, a, "critical", state="resolved", kev=True, risk=99)  # not open
    r = _rows(_body(w, root))[_sid(deal)]
    assert r["open_findings"] == {"critical": 1, "high": 2, "medium": 2, "low": 1, "unknown": 1}
    assert r["worst_severity"] == "critical"
    assert r["kev"] == 2
    assert r["risk_score_sum"] == 165


def test_a_resolved_finding_alone_does_not_count_but_the_open_twin_does(w):
    root = w.ours()
    deal = _acquired(w, root, date(2025, 1, 1), "day")
    d = _claim(w, root, "domain", aff=deal)
    a = _asset(w, "g.example.com", d.target_id)
    _finding(w, a, "high", state="resolved")
    r = _rows(_body(w, root))[_sid(deal)]
    assert r["open_findings"]["high"] == 0 and r["worst_severity"] is None
    _finding(w, a, "high", state="open")
    assert _rows(_body(w, root))[_sid(deal)]["open_findings"]["high"] == 1


def test_a_finding_excluded_from_main_does_not_count_but_the_unverified_twin_does(w):
    root = w.ours()
    deal = _acquired(w, root, date(2025, 1, 1), "day")
    d = _claim(w, root, "domain", aff=deal)
    a = _asset(w, "h.example.com", d.target_id)
    _finding(w, a, "high", verification="rejected_shared_infra", risk=50, kev=True)
    _finding(w, a, "high", verification="ownership_unverifiable", risk=50)
    r = _rows(_body(w, root))[_sid(deal)]
    assert (r["open_findings"]["high"], r["kev"], r["risk_score_sum"]) == (0, 0, 0)
    _finding(w, a, "high", verification=None, risk=7)
    r = _rows(_body(w, root))[_sid(deal)]
    assert (r["open_findings"]["high"], r["risk_score_sum"]) == (1, 7)


def test_worst_severity_is_none_for_a_row_without_findings_and_low_when_only_low(w):
    root = w.ours()
    deal = _acquired(w, root, date(2025, 1, 1), "day")
    d = _claim(w, root, "domain", aff=deal)
    a = _asset(w, "i.example.com", d.target_id)
    assert _rows(_body(w, root))[_sid(deal)]["worst_severity"] is None
    _finding(w, a, "low")
    assert _rows(_body(w, root))[_sid(deal)]["worst_severity"] == "low"


# ── 5. share ────────────────────────────────────────────────────────────────


def test_shares_sum_to_one_and_a_null_risk_adds_zero(w):
    root = w.ours()
    d1, d2 = _acquired(w, root, date(2025, 1, 1), "day"), _acquired(w, root, date(2025, 2, 1), "day")
    c1, c2, c3 = _claim(w, root, "domain", aff=d1), _claim(w, root, "domain", aff=d2), _claim(w, root, "domain")
    _finding(w, _asset(w, "s1.example.com", c1.target_id), "high", risk=30)
    _finding(w, _asset(w, "s2.example.com", c2.target_id), "high", risk=60)
    _finding(w, _asset(w, "s3.example.com", c3.target_id), "high", risk=10)
    _finding(w, _asset(w, "s4.example.com", c3.target_id), "high", risk=None)
    body = _body(w, root)
    rows = _rows(body)
    assert body["estate_risk_score_sum"] == 100
    assert rows[None]["risk_score_sum"] == 10 and rows[None]["open_findings"]["high"] == 2
    assert [rows[_sid(d1)]["risk_share"], rows[_sid(d2)]["risk_share"], rows[None]["risk_share"]] == pytest.approx(
        [0.3, 0.6, 0.1])
    assert sum(r["risk_share"] for r in body["rows"]) == pytest.approx(1.0)


def test_every_share_is_null_when_the_estate_sum_is_zero(w):
    root = w.ours()
    deal = _acquired(w, root, date(2025, 1, 1), "day")
    d = _claim(w, root, "domain", aff=deal)
    body = _body(w, root)
    assert body["estate_risk_score_sum"] == 0 and all(r["risk_share"] is None for r in body["rows"])
    _finding(w, _asset(w, "z.example.com", d.target_id), "high", risk=0)  # open finding, risk 0
    body = _body(w, root)
    assert _rows(body)[_sid(deal)]["open_findings"]["high"] == 1  # reached: counted, but risk is 0
    assert body["estate_risk_score_sum"] == 0 and all(r["risk_share"] is None for r in body["rows"])
    _finding(w, _asset(w, "z2.example.com", d.target_id), "high", risk=5)
    body = _body(w, root)
    assert _rows(body)[_sid(deal)]["risk_share"] == 1.0 and _rows(body)[None]["risk_share"] == 0.0


# ── 6. no claimed scope ─────────────────────────────────────────────────────


def test_a_deal_with_no_claimed_scope_is_an_all_zero_row(w):
    root = w.ours()
    deal = _acquired(w, root, date(2025, 1, 1), "day")
    empty = _rows(_body(w, root))[_sid(deal)]
    assert empty["name"] == deal.legal_name
    assert {k: v for k, v in empty.items() if isinstance(v, int) and not isinstance(v, bool)} == {
        k: 0 for k in ("domains_claimed", "domains_to_review", "asns_claimed", "cidrs_claimed", "ip_to_review",
                       "assets", "kev", "risk_score_sum")}
    assert empty["postures"] == [] and empty["worst_severity"] is None
    assert empty["open_findings"] == {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    _claim(w, root, "domain", aff=deal)
    assert _rows(_body(w, root))[_sid(deal)]["domains_claimed"] == 1


def test_postures_are_the_claimed_targets_engagement_postures_or_estate(w):
    root = w.ours()
    deal = _acquired(w, root, date(2025, 1, 1), "day")
    d1, d2 = _claim(w, root, "domain", aff=deal), _claim(w, root, "domain", aff=deal)
    assert _rows(_body(w, root))[_sid(deal)]["postures"] == ["estate"]
    eng = w.engagement("pre_close")
    w.db.query(Target).filter(Target.id == d1.target_id).update({"engagement_id": eng.id})
    w.db.commit()
    assert _rows(_body(w, root))[_sid(deal)]["postures"] == ["estate", "pre_close"]
    w.db.query(Target).filter(Target.id == d2.target_id).update({"engagement_id": eng.id})
    w.db.commit()
    assert _rows(_body(w, root))[_sid(deal)]["postures"] == ["pre_close"]
    assert _rows(_body(w, root))[None]["postures"] == []
    assert w.db.get(Engagement, eng.id) is not None


# ── 7. read scope ───────────────────────────────────────────────────────────


@pytest.fixture
def scoped(w):
    root = w.ours()
    deal = _acquired(w, root, date(2025, 1, 1), "day")
    d = _claim(w, root, "domain", aff=deal)
    _in_review(w, root)  # organic, to review
    a = _asset(w, "r.example.com", d.target_id)
    _finding(w, a, "high", risk=20)
    w.root, w.deal = root, deal
    return w


def test_the_unscoped_baseline_counts_everything(scoped):
    rows = _rows(_body(scoped, scoped.root))
    assert rows[_sid(scoped.deal)]["assets"] == 1 and rows[_sid(scoped.deal)]["open_findings"]["high"] == 1
    assert rows[_sid(scoped.deal)]["risk_share"] == 1.0
    assert rows[_sid(scoped.deal)]["domains_claimed"] == 1 and rows[None]["domains_to_review"] == 1


def test_asset_clause_false_hides_assets_findings_and_the_shares(scoped, monkeypatch):
    monkeypatch.setattr(read_scope, "asset_clause", lambda user, asset: false())
    body = _body(scoped, scoped.root)
    r = _rows(body)[_sid(scoped.deal)]
    assert r["domains_claimed"] == 1  # reached: the claim is still read
    assert (r["assets"], r["open_findings"]["high"], r["risk_score_sum"]) == (0, 0, 0)
    assert body["estate_risk_score_sum"] == 0 and all(x["risk_share"] is None for x in body["rows"])


def test_finding_clause_false_hides_findings_but_not_assets(scoped, monkeypatch):
    monkeypatch.setattr(read_scope, "finding_clause", lambda user, finding, asset: false())
    body = _body(scoped, scoped.root)
    r = _rows(body)[_sid(scoped.deal)]
    assert (r["assets"], r["open_findings"]["high"], r["kev"], r["risk_score_sum"]) == (1, 0, 0, 0)
    assert all(x["risk_share"] is None for x in body["rows"])


def test_an_asset_the_caller_cannot_read_is_not_counted_while_its_neighbour_is(w, monkeypatch):
    root = w.ours()
    deal = _acquired(w, root, date(2025, 1, 1), "day")
    d = _claim(w, root, "domain", aff=deal)
    seen, hidden = _asset(w, "seen.example.com", d.target_id), _asset(w, "hidden.example.com", d.target_id)
    _finding(w, seen, "low", risk=1)
    _finding(w, hidden, "critical", risk=100, kev=True)
    r = _rows(_body(w, root))[_sid(deal)]
    assert (r["assets"], r["open_findings"]["critical"], r["kev"], r["risk_score_sum"]) == (2, 1, 1, 101)  # reached
    monkeypatch.setattr(read_scope, "asset_clause", lambda user, asset: asset.value != "hidden.example.com")
    r = _rows(_body(w, root))[_sid(deal)]
    assert (r["assets"], r["open_findings"]["critical"], r["open_findings"]["low"], r["kev"], r["risk_score_sum"]) == (
        1, 0, 1, 0, 1)


def test_domain_clause_false_hides_claimed_and_to_review(scoped, monkeypatch):
    monkeypatch.setattr(read_scope, "domain_clause", lambda user, domain: false())
    body = _body(scoped, scoped.root)
    assert len(body["rows"]) == 2  # the tree is not behind domain_clause: the deal row stays, all zero
    for r in body["rows"]:
        assert (r["domains_claimed"], r["domains_to_review"], r["assets"], r["open_findings"]["high"]) == (0, 0, 0, 0)
        assert r["risk_share"] is None


def test_an_invisible_root_and_an_unknown_org_are_404(scoped, monkeypatch):
    w = scoped
    assert _get(w, w.root).status_code == 200
    outsider = w.user(VIEWER)
    monkeypatch.setattr(
        read_scope, "entity_clause",
        lambda user, entity: read_scope.true() if user.id != outsider.id else entity.id != w.root.id,
    )
    assert _get(w, w.root, headers=w.headers(user=outsider)).status_code == 404
    assert _get(w, w.root).status_code == 200
    r = client.get(f"/api/organizations/{uuid.uuid4()}/acquisitions", headers=w.headers(role=VIEWER))
    assert r.status_code == 404


def test_a_company_that_is_not_a_root_is_404(w):
    root = w.ours()
    deal = _acquired(w, root, date(2025, 1, 1), "day")
    assert _get(w, root).status_code == 200
    assert _get(w, deal).status_code == 404


# ── 8. reassigned-away records ──────────────────────────────────────────────


def test_a_reassigned_away_record_leaves_the_rollup_unchanged(w):
    import ipaddress

    root = w.ours()
    deal = _acquired(w, root, date(2025, 1, 1), "day")
    c = _claim(w, root, "cidr", aff=deal, n=5)
    a = _asset(w, "198.51.100.9", c.target_id)
    _finding(w, a, "high", risk=33)
    before = _get(w, root).text
    lower, _upper = ipaddress.ip_network(c.value).subnets(prefixlen_diff=1)
    ev = w.evidence_row()
    record_reassignment(w.db, candidate_id=c.id, found=Reassigned(str(lower), "org", "EXAMPLE-B"),
                        evidence_id=ev.id, now=NOW)
    w.db.commit()
    from app.models.scope_candidate import ScopeCandidateReassignment

    assert w.db.query(ScopeCandidateReassignment).filter_by(candidate_id=c.id).count() == 1  # reached
    assert _get(w, root).text == before
    assert _rows(json_of(before))[_sid(deal)]["cidrs_claimed"] == 1


def json_of(text_):
    import json

    return json.loads(text_)


# ── 9. in review ────────────────────────────────────────────────────────────


def test_candidates_in_review_count_in_to_review_only(w):
    root = w.ours()
    deal = _acquired(w, root, date(2025, 1, 1), "day")
    review_domain = _in_review(w, root, "domain")
    review_cidr = _in_review(w, root, "cidr", n=6)
    # an open candidate under the deal's affiliate: written through a signal via the deal's company
    via_deal = w.candidate(root, via=deal)
    body = _body(w, root)
    rows = _rows(body)
    assert rows[_sid(deal)]["domains_to_review"] == 1  # via_deal: default affiliate is its signal's company
    assert rows[None]["domains_to_review"] == 1 and rows[None]["ip_to_review"] == 1
    assert all(r["domains_claimed"] == r["cidrs_claimed"] == r["assets"] == 0 for r in body["rows"])
    # a target for an open candidate's value, with an asset: not claimed, so never counted
    t = Target(id=uuid.uuid4(), value=review_domain.value, type="domain", source_type="test", entity_id=root.id)
    w.db.add(t)
    w.db.commit()
    w.track_target(t.value)
    a = _asset(w, "review.example.com", t.id)
    _finding(w, a, "critical", risk=80)
    body = _body(w, root)
    assert all(r["assets"] == 0 and r["open_findings"]["critical"] == 0 for r in body["rows"])
    assert body["estate_risk_score_sum"] == 0
    # once claimed it leaves to-review and its asset counts
    cd.claim(w.db, candidate_id=review_domain.id, user=w.user())
    rows = _rows(_body(w, root))
    assert rows[None]["domains_to_review"] == 0 and rows[None]["domains_claimed"] == 1
    assert rows[None]["assets"] == 1 and rows[None]["open_findings"]["critical"] == 1
    assert review_cidr.id and via_deal.id


def test_a_lead_below_the_bar_is_not_to_review(w):
    root = w.ours()
    cand = _cidr(w, root, 7, signal_type="peeringdb_website_claimed")  # one Supporting family: a lead
    st = w.db.get(ScopeCandidate, cand.id)
    assert st.status == "open"
    assert cd._strength_row(w.db, cand.id).proposable is False  # reached: a real lead, below the bar
    assert _rows(_body(w, root))[None]["ip_to_review"] == 0


# ── the tree's new field ────────────────────────────────────────────────────


def test_org_tree_carries_the_relations_precision_for_confirmed_and_proposed(w):
    root = w.ours()
    conf = _acquired(w, root, date(2025, 1, 1), "month")
    prop = _acquired(w, root, date(2025, 2, 1), "year", confirm=False)
    nodes = {n.entity_id: n for n in org_tree.org_tree(w.db, w.user(), root.id)}
    assert nodes[root.id].event_date_precision is None
    assert (nodes[conf.id].status, nodes[conf.id].event_date_precision) == ("confirmed", "month")
    assert (nodes[prop.id].status, nodes[prop.id].event_date_precision) == ("proposed", "year")


# ── rollup.py, pure ─────────────────────────────────────────────────────────


def _n(entity_id, parent_id, relation, status="confirmed"):
    return org_tree.TreeNode(entity_id, "n", parent_id, relation, None, status, 0)


def _ids(k):
    return [uuid.UUID(int=i + 1) for i in range(k)]


def test_deal_of_nearest_acquired_ancestor_or_self():
    root, a, sub_a, b, sub_root, p, sub_p = _ids(7)
    nodes = [
        _n(root, None, None), _n(a, root, "acquired"), _n(sub_a, a, "subsidiary_of"), _n(b, a, "acquired"),
        _n(sub_root, root, "subsidiary_of"), _n(p, root, "acquired", "proposed"), _n(sub_p, p, "subsidiary_of", "proposed"),
    ]
    got = rollup.deal_of(nodes)
    assert got == {root: None, a: a, sub_a: a, b: b, sub_root: None}
    assert p not in got and sub_p not in got  # proposed nodes are not mapped at all


def test_deal_of_a_subsidiary_below_a_nested_acquisition_goes_to_the_nested_one():
    root, a, b, sub_b = _ids(4)
    nodes = [_n(root, None, None), _n(a, root, "acquired"), _n(b, a, "acquired"), _n(sub_b, b, "subsidiary_of")]
    assert rollup.deal_of(nodes)[sub_b] == b


def test_deal_of_survives_a_cycle():
    x, y = _ids(2)
    assert rollup.deal_of([_n(x, y, "subsidiary_of"), _n(y, x, "subsidiary_of")]) == {x: None, y: None}


def test_attribute_rank_then_decided_at_then_id():
    c_dom, c_cidr, c_asn, d_early, d_late = _ids(5)
    t = {k: uuid.uuid4() for k in "abcde"}
    asset = uuid.uuid4()
    early, late = NOW - timedelta(days=1), NOW
    claims = [
        rollup.Claim(c_asn, "asn", t["a"], early), rollup.Claim(c_cidr, "cidr", t["b"], early),
        rollup.Claim(d_late, "domain", t["d"], late), rollup.Claim(d_early, "domain", t["c"], early),
    ]
    every = [(t[k], asset) for k in "abcd"]
    assert rollup.attribute(claims, every) == {asset: d_early}
    assert rollup.attribute(claims, [(t["a"], asset), (t["b"], asset)]) == {asset: c_cidr}
    assert rollup.attribute(claims, [(t["a"], asset)]) == {asset: c_asn}
    assert rollup.attribute(claims, [(t["d"], asset), (t["c"], asset)]) == {asset: d_early}
    # equal rank and time: the lower candidate id
    tie = [rollup.Claim(d_late, "domain", t["d"], late), rollup.Claim(d_early, "domain", t["e"], late)]
    assert rollup.attribute(tie, [(t["d"], asset), (t["e"], asset)]) == {asset: d_early}
    assert rollup.attribute(tie, [(uuid.uuid4(), asset)]) == {}  # a link to no claimed target
