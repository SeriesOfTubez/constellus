"""Org-discovery reverse-IP generator (planning#277 S1b part C).

Offline: the pDNS answer is a `reverse_ip` claim seeded directly on the
ip_address asset (fresh, so `reverse_ip_domains` serves it from cache and never
reaches mnemonic). Synthetic names and RFC 5737 / RFC 3849 addresses only.

Run with:  scripts/test.sh app/tests/test_org_discovery_reverse_ip.py
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.claim import ClaimHistory
from app.models.scan import ScanRun, ScanStatus
from app.models.scope_candidate import ScopeCandidate, ScopeSignal
from app.models.target import Target
from app.services import hosting_classifier as hc
from app.services import scan_executor
from app.services.claim_emitter import upsert_single_claim
from app.services.org_discovery import candidates as cd
from app.services.org_discovery import generators, runner
from app.tests import _docaddr
from app.tests._org_world import World, hexid


@pytest.fixture
def w():
    world = World()
    assets: list[uuid.UUID] = []
    world.reverse_ip_assets = assets
    try:
        yield world
    finally:
        world.close()
        db = SessionLocal()
        try:
            if assets:
                db.query(ClaimHistory).filter(ClaimHistory.asset_canonical_id.in_(assets)).delete(synchronize_session=False)
                db.query(AssetCanonical).filter(AssetCanonical.id.in_(assets)).delete(synchronize_session=False)
                db.commit()
        finally:
            db.close()


def _dom(tag="") -> str:
    # a registrable domain of its own (the PSL would fold `x.example.net` to `example.net`)
    return f"org277-{tag}{hexid()}.com"


def _claimed(w, root, value):
    c = w.candidate(root, value=value)
    result = cd.claim(w.db, candidate_id=c.id, user=w.user())
    w.track_target(result.target.value)
    w.db.commit()
    return c


def _iso(delta_days: float) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=delta_days)).isoformat()


def _asset(w, **kw) -> AssetCanonical:
    now = datetime.now(timezone.utc)
    row = AssetCanonical(id=uuid.uuid4(), first_seen_at=now, last_seen_at=now, **kw)
    w.db.add(row)
    w.db.commit()
    w.reverse_ip_assets.append(row.id)
    return row


def _seed(w, domain, ip, records, sharing="dedicated", *, with_ip_asset=True, with_claim=True):
    """The claimed domain's own A record, its ip_address asset and (optionally) a cached reverse_ip claim.
    `records` is a list of (hostname, first_seen_days_ago, last_seen_days_ago)."""
    _asset(w, asset_type="dns_record", value=domain, record_type="A", content=ip)
    ip_asset = _asset(w, asset_type="ip_address", value=ip) if with_ip_asset else None
    if ip_asset is not None and with_claim:
        recs = [{"domain": d, "first_seen": _iso(f), "last_seen": _iso(l)} for d, f, l in records]
        upsert_single_claim(
            w.db, ip_asset.id, "hosting_classifier", "reverse_ip",
            {
                "source": "mnemonic", "count": len(recs), "domains": [r["domain"] for r in recs], "records": recs,
                "active_count": len(recs), "truncated": False, "sharing": sharing,
            },
            datetime.now(timezone.utc),
        )
        w.db.commit()


def _ip() -> str:
    return _docaddr.alloc()  # collision-free RFC 5737 / 3849 address


def _signals(candidate_id):
    db = SessionLocal()
    try:
        return list(db.execute(select(ScopeSignal).where(ScopeSignal.candidate_id == candidate_id)).scalars())
    finally:
        db.close()


def _run_gen(w, claimed):
    w.db.refresh(claimed)
    result = generators.record_reverse_ip(w.db, claimed=claimed)
    w.db.commit()
    return result


@pytest.fixture
def ip():
    return _ip()


# ── the generator ───────────────────────────────────────────────────────────


def test_a_dedicated_active_overlapping_neighbour_becomes_a_lead(w, ip):
    root = w.ours()
    mine, other = _dom("m"), _dom("o")
    claimed = _claimed(w, root, mine)
    _seed(w, mine, ip, [(mine, 400, 1), (other, 300, 2)])

    result = _run_gen(w, claimed)

    assert (result.ips_checked, result.signals_recorded, result.not_dedicated, result.no_claim) == (1, 1, 0, 0)
    lead = w.db.execute(
        select(ScopeCandidate).where(ScopeCandidate.root_entity_id == root.id, ScopeCandidate.value == other)
    ).scalar_one()
    assert result.created_candidate_ids == [lead.id] and lead.status == "open"
    (sig,) = _signals(lead.id)
    assert sig.signal_type == "reverse_ip_dedicated" and sig.matched_values == [ip]
    assert sig.anchor_kind == "claimed_candidate" and sig.anchor_candidate_id == claimed.id
    assert other in sig.quote and mine in sig.quote and ip in sig.quote


@pytest.mark.parametrize("verdict", ["shared", "historically_shared", "unknown"])
def test_a_verdict_other_than_dedicated_records_nothing_but_the_claim_was_read(w, ip, verdict):
    root = w.ours()
    mine, other = _dom("m"), _dom("o")
    claimed = _claimed(w, root, mine)
    _seed(w, mine, ip, [(mine, 400, 1), (other, 300, 2)], sharing=verdict)
    result = _run_gen(w, claimed)
    assert (result.ips_checked, result.not_dedicated, result.signals_recorded) == (1, 1, 0)
    assert result.created_candidate_ids == []
    assert w.db.execute(select(ScopeCandidate).where(ScopeCandidate.value == other)).first() is None


def test_an_inactive_record_is_skipped(w, ip):
    root = w.ours()
    mine, other = _dom("m"), _dom("o")
    claimed = _claimed(w, root, mine)
    _seed(w, mine, ip, [(mine, 900, 1), (other, 900, 400)])  # last seen beyond the 365-day window
    result = _run_gen(w, claimed)
    assert (result.signals_recorded, result.skipped_inactive_or_previous_tenant) == (0, 1)


def test_a_previous_tenant_is_skipped_and_only_the_dates_decide_it(w, ip):
    root = w.ours()
    mine, other = _dom("m"), _dom("o")
    claimed = _claimed(w, root, mine)
    # `other` is active (last seen 100d ago) but left before the claimed domain arrived (first seen 50d ago)
    _seed(w, mine, ip, [(mine, 50, 1), (other, 200, 100)])
    result = _run_gen(w, claimed)
    assert (result.signals_recorded, result.skipped_inactive_or_previous_tenant) == (0, 1)

    # the same fixture with the claimed domain arriving earlier: the two overlapped, so it is proposed
    w2 = w
    root2 = w2.ours()
    mine2, other2, ip2 = _dom("m"), _dom("o"), _ip()
    claimed2 = _claimed(w2, root2, mine2)
    _seed(w2, mine2, ip2, [(mine2, 150, 1), (other2, 200, 100)])
    result2 = _run_gen(w2, claimed2)
    assert (result2.signals_recorded, result2.skipped_inactive_or_previous_tenant) == (1, 0)


def test_an_address_where_pdns_never_saw_the_claimed_domain_proposes_nothing(w, ip):
    root = w.ours()
    mine, other = _dom("m"), _dom("o")
    claimed = _claimed(w, root, mine)
    # the positive fixture minus the claimed domain's own record: `other` is
    # active, but nothing shows the two were on the address at the same time
    _seed(w, mine, ip, [(other, 300, 2)])
    result = _run_gen(w, claimed)
    assert (result.ips_checked, result.not_dedicated, result.no_claim) == (1, 0, 0)  # the claim was read
    assert (result.no_claimed_history, result.signals_recorded) == (1, 0)
    assert w.db.execute(select(ScopeCandidate).where(ScopeCandidate.value == other)).first() is None


def test_hosts_fold_to_their_apex_and_own_or_other_claimed_domains_are_never_proposed(w, ip):
    root = w.ours()
    mine, sibling, other = _dom("m"), _dom("s"), _dom("o")
    claimed = _claimed(w, root, mine)
    _claimed(w, root, sibling)
    _seed(w, mine, ip, [
        (mine, 400, 1), (f"www.{mine}", 400, 1), (f"www.{other}", 300, 2), (f"mail.{other}", 300, 3),
        (sibling, 300, 1), (f"api.{sibling}", 300, 1),
    ])
    result = _run_gen(w, claimed)
    assert result.signals_recorded == 1
    proposed = {
        v for (v,) in w.db.execute(
            select(ScopeCandidate.value).where(ScopeCandidate.root_entity_id == root.id, ScopeCandidate.status == "open")
        )
    }
    assert other in proposed and mine not in proposed and sibling not in proposed
    assert not any(v.startswith(("www.", "mail.", "api.")) for v in proposed)
    sig = [s for c in w.db.execute(select(ScopeCandidate.id).where(ScopeCandidate.value == other)).scalars() for s in _signals(c)]
    assert len(sig) == 1


def test_no_ip_asset_or_no_claim_records_nothing_and_is_counted(w, ip, monkeypatch):
    root = w.ours()
    mine = _dom("m")
    claimed = _claimed(w, root, mine)
    _seed(w, mine, ip, [], with_ip_asset=False)
    result = _run_gen(w, claimed)
    assert (result.ips_checked, result.signals_recorded, result.no_claim) == (0, 0, 0)

    # an ip asset with no cached claim and no budget to fetch one: counted as no_claim, never fetched
    monkeypatch.setattr(hc, "_spend_reverse_ip_budget", lambda: False)
    monkeypatch.setattr(hc, "connector_get", lambda *a, **k: pytest.fail("must not fetch"))
    mine2, ip2 = _dom("m"), _ip()
    claimed2 = _claimed(w, root, mine2)
    _seed(w, mine2, ip2, [], with_claim=False)
    result2 = _run_gen(w, claimed2)
    assert (result2.ips_checked, result2.no_claim, result2.signals_recorded) == (1, 1, 0)


def test_a_claimed_that_is_not_claimed_yields_an_empty_result(w, ip):
    root = w.ours()
    mine = _dom("m")
    open_c = w.candidate(root, value=mine)
    _seed(w, mine, ip, [(mine, 400, 1), (_dom("o"), 300, 2)])
    assert generators.record_reverse_ip(w.db, claimed=open_c) == generators.ReverseIpResult()


def test_a_rerun_resights_and_creates_nothing(w, ip):
    root = w.ours()
    mine, other = _dom("m"), _dom("o")
    claimed = _claimed(w, root, mine)
    _seed(w, mine, ip, [(mine, 400, 1), (other, 300, 2)])
    first = _run_gen(w, claimed)
    second = _run_gen(w, claimed)
    assert (first.signals_recorded, second.signals_recorded, second.signals_resighted) == (1, 0, 1)
    assert second.created_candidate_ids == []
    lead = w.db.execute(select(ScopeCandidate.id).where(ScopeCandidate.value == other)).scalar_one()
    assert len(_signals(lead)) == 1


def test_a_claim_read_does_not_fetch_or_spend_budget(w, ip, monkeypatch):
    monkeypatch.setattr(hc, "_spend_reverse_ip_budget", lambda: pytest.fail("spent"))
    monkeypatch.setattr(hc, "connector_get", lambda *a, **k: pytest.fail("fetched"))
    assert hc.reverse_ip_claim(w.db, ip) is None  # no asset
    _seed(w, _dom("m"), ip, [("x.example.com", 5, 1)])
    got = hc.reverse_ip_claim(w.db, ip)
    assert got is not None and got["sharing"] == "dedicated" and got["domains"] == ["x.example.com"]


# ── the runner ──────────────────────────────────────────────────────────────


def test_the_runner_verifies_exactly_the_created_leads(w, ip, monkeypatch):
    root = w.ours()
    mine, other = _dom("m"), _dom("o")
    claimed = _claimed(w, root, mine)
    _seed(w, mine, ip, [(mine, 400, 1), (other, 300, 2)])
    seen: list = []
    monkeypatch.setattr(runner, "verify_new_candidates", lambda ids: seen.append(list(ids)))

    result = runner.reverse_ip_for_claimed(claimed.id)

    lead = w.db.execute(select(ScopeCandidate.id).where(ScopeCandidate.value == other)).scalar_one()
    assert seen == [[lead]] and result.created_candidate_ids == [lead]
    seen.clear()
    runner.reverse_ip_for_claimed(claimed.id)  # a re-run creates nothing: nothing to verify
    assert seen == []


def test_a_failure_inside_the_generator_rolls_back_and_does_not_raise(w, monkeypatch):
    root = w.ours()
    claimed = _claimed(w, root, _dom("m"))
    seen: list = []
    monkeypatch.setattr(runner, "verify_new_candidates", lambda ids: seen.append(ids))

    def boom(db, **kw):
        db.add(ScopeCandidate(root_entity_id=root.id, kind="domain", value=_dom("z"), status="open"))
        db.flush()
        raise RuntimeError("generator exploded")

    monkeypatch.setattr(generators, "record_reverse_ip", boom)
    result = runner.reverse_ip_for_claimed(claimed.id)
    assert result.created_candidate_ids == [] and seen == []
    assert w.db.execute(select(ScopeCandidate).where(
        ScopeCandidate.root_entity_id == root.id, ScopeCandidate.status == "open")).first() is None


def test_verify_after_claim_runs_reverse_ip_even_with_no_open_candidates_and_swallows_its_failure(w, monkeypatch):
    root = w.ours()
    claimed = _claimed(w, root, _dom("m"))
    calls: list = []
    monkeypatch.setattr(runner, "reverse_ip_for_claimed", lambda cid: calls.append(cid))
    report = runner.verify_after_claim(claimed.id)
    assert calls == [claimed.id] and report.pairs_checked == 0

    def boom(cid):
        raise RuntimeError("reverse ip exploded")

    monkeypatch.setattr(runner, "reverse_ip_for_claimed", boom)
    assert runner.verify_after_claim(claimed.id).pairs_checked == 0  # did not raise


# ── the post-discovery hook ─────────────────────────────────────────────────


def test_the_hook_selects_only_claimed_candidates_on_in_scope_targets(w, monkeypatch):
    # An OURS root: its claims land in the estate (engagement NULL). The first
    # version of the hook read `scope_target_engagements`, which only stamps
    # targets WITH an engagement, and so never fired for an ours org.
    root = w.ours()
    in_scope = _claimed(w, root, _dom("a"))
    out_of_scope = _claimed(w, root, _dom("b"))
    open_in_scope = w.candidate(root, value=_dom("c"))
    in_row = w.db.get(ScopeCandidate, in_scope.id)
    in_target = w.db.get(Target, in_row.target_id)
    assert in_target is not None and in_target.engagement_id is None
    assert w.db.get(ScopeCandidate, out_of_scope.id).target_id not in (None, in_target.id)
    # an OPEN candidate whose value is in scope would be wrong to pass; make the trap real
    assert w.db.get(ScopeCandidate, open_in_scope.id).status == "open"
    passed: list = []
    monkeypatch.setattr(runner, "reverse_ip_for_claimed", lambda cid: passed.append(cid))

    scan_executor._org_discovery_reverse_ip(w.db, {"domains": [in_target.value, _dom("c")], "ip_ranges": []})

    assert passed == [in_scope.id]
    assert out_of_scope.id not in passed and open_in_scope.id not in passed

    passed.clear()
    scan_executor._org_discovery_reverse_ip(w.db, {"domains": [], "ip_ranges": []})
    assert passed == []


def _scan_run(w, options, scope_domain) -> uuid.UUID:
    db = SessionLocal()
    try:
        run = ScanRun(id=uuid.uuid4(), status=ScanStatus.PENDING, scope={"domains": [scope_domain], "ip_ranges": []}, options=options,
                      created_by_id=w.user().id)
        db.add(run)
        db.commit()
        return run.id
    finally:
        db.close()


@pytest.mark.parametrize("skip, expected", [(True, 0), (False, 1)])
def test_the_hook_runs_after_discovery_and_not_when_discovery_is_skipped(w, monkeypatch, skip, expected):
    scope = {"domains": [_dom("scan")], "ip_ranges": []}  # non-empty, or `_run` returns before the post-scan steps
    run_id = _scan_run(w, {"skip_discovery": skip}, scope["domains"][0])
    calls: list = []
    monkeypatch.setattr(scan_executor, "_run_pipeline", lambda *a, **k: None)
    monkeypatch.setattr(scan_executor, "_org_discovery_reverse_ip", lambda db, scope: calls.append(scope))
    db = SessionLocal()
    try:
        scan_executor._run(db, run_id, scope, {})
    finally:
        db.close()
    assert len(calls) == expected
