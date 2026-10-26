"""The `rir_allocation_dedicated_ip` generator (planning#278 S3c1).

Offline: the pDNS verdict is a `reverse_ip` claim seeded directly on the
ip_address asset, read by the generator through the read-only
`reverse_ip_claim`. Synthetic data only: RFC 3849 prefixes (`2001:db8:278:N::/64`,
as `test_org_discovery_asn_cidr._net`). No IPv4 case: the `_docaddr` /29 pool is fully
drawn by other modules, and the docaddr guard rejects IPv4 prefix literals.

Run with:  scripts/test.sh app/tests/test_org_discovery_rir_dedicated_ip.py
"""

import ipaddress
import json
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import func, select

from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.claim import ClaimHistory
from app.models.cloud_range import CloudRangeMeta
from app.models.evidence import EvidenceBlob, EvidenceFetch
from app.models.scope_candidate import ScopeCandidate, ScopeSignal
from app.services import hosting_classifier as hc
from app.services import scan_executor
from app.services.claim_emitter import upsert_single_claim
from app.services.org_discovery import candidates as cd
from app.services.org_discovery import generators, runner
from app.services.org_discovery import strength as strength_sql
from app.tests._org_world import World, hexid
from app.tests.test_org_discovery_asn_cidr import _Meta

HANDLE = "EXAMPLE-HOLDINGS-A"
RULE = "rir_allocation_dedicated_ip"


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


@pytest.fixture(autouse=True)
def meta(w):
    # claiming a CIDR needs the cloud-ranges dataset loaded (as in the asn/cidr tests)
    m = _Meta(w.db)
    had = w.db.get(CloudRangeMeta, True) is not None
    m.add()
    yield m
    w.db.rollback()
    if not had:
        m.remove()


def _net(n: int) -> str:
    return str(ipaddress.ip_network(f"2001:db8:278:{n:x}::/64"))


def _v6(n: int, host: int = 5) -> str:
    return str(ipaddress.ip_address(f"2001:db8:278:{n:x}::{host:x}"))


def _dom(tag="") -> str:
    return f"org278-{tag}{hexid()}.com"


def _claimed(w, root, value):
    c = w.candidate(root, value=value)
    result = cd.claim(w.db, candidate_id=c.id, user=w.user())
    w.track_target(result.target.value)
    w.db.commit()
    return c


def _asset(w, **kw) -> AssetCanonical:
    now = datetime.now(timezone.utc)
    row = AssetCanonical(id=uuid.uuid4(), first_seen_at=now, last_seen_at=now, **kw)
    w.db.add(row)
    w.db.commit()
    w.reverse_ip_assets.append(row.id)
    return row


def _seed(w, domain, ip, sharing="dedicated", *, with_ip_asset=True, with_claim=True):
    """The domain's own A/AAAA record, its ip_address asset and (optionally) a
    cached reverse_ip claim with the real value shape."""
    _asset(w, asset_type="dns_record", value=domain, record_type="AAAA" if ":" in ip else "A", content=ip)
    ip_asset = _asset(w, asset_type="ip_address", value=ip) if with_ip_asset else None
    if ip_asset is not None and with_claim:
        recs = [{"domain": domain, "first_seen": datetime.now(timezone.utc).isoformat(),
                 "last_seen": datetime.now(timezone.utc).isoformat()}]
        upsert_single_claim(
            w.db, ip_asset.id, "hosting_classifier", "reverse_ip",
            {
                "source": "mnemonic", "count": len(recs), "domains": [r["domain"] for r in recs], "records": recs,
                "active_count": len(recs), "truncated": False, "sharing": sharing,
            },
            datetime.now(timezone.utc),
        )
        w.db.commit()


def _record(w, root, value, kind, *, handle=HANDLE, rir="ripe", signal_type="rir_contact_email_unvalidated"):
    ev = w.evidence_row()
    quote = f"inetnum: {ipaddress.ip_network(value).network_address}" if kind == "cidr" else f"aut-num: {value}"
    out = cd.record_signal(
        w.db, root_entity_id=root.id, value=value, kind=kind, rir=rir, rir_handle=handle,
        signal_type=signal_type, anchor_kind="person", via_entity_id=root.id, evidence_id=ev.id, quote=quote,
    )
    w.db.commit()
    return out.candidate


def _cidr(w, root, value, **kw) -> ScopeCandidate:
    return _record(w, root, value, "cidr", **kw)


def _signals(candidate_id, signal_type=RULE):
    db = SessionLocal()
    try:
        return list(db.execute(select(ScopeSignal).where(
            ScopeSignal.candidate_id == candidate_id, ScopeSignal.signal_type == signal_type)).scalars())
    finally:
        db.close()


def _strength(db, cand):
    s = strength_sql.strength_subquery(candidate_ids=[cand.id])
    row = db.execute(select(s.strength.label("strength"), s.proposable.label("proposable"))).one()
    return row.strength, bool(row.proposable)


def _sweep(w, root):
    result = generators.record_rir_dedicated_ip(w.db, root_entity_id=root.id)
    w.db.commit()
    return result


def _count(w, root):
    return w.db.execute(select(func.count()).select_from(ScopeCandidate).where(
        ScopeCandidate.root_entity_id == root.id)).scalar_one()


@pytest.fixture
def no_fetch(monkeypatch):
    """Spies on the transport and on the fetching entry point: a sweep must touch neither."""
    seen: list = []

    def boom(*a, **k):
        seen.append((a, k))
        raise AssertionError("the sweep must never fetch")

    monkeypatch.setattr(hc, "reverse_ip_domains", boom)
    monkeypatch.setattr(hc, "connector_get", boom)
    return seen


# ── the generator ───────────────────────────────────────────────────────────


def test_a_dedicated_ipv6_address_inside_an_open_cidr_candidate_becomes_a_supporting_signal(w, no_fetch):
    root = w.ours()
    mine = _dom("m")
    claimed = _claimed(w, root, mine)
    ip = _v6(1)
    cand = _cidr(w, root, _net(1))
    _seed(w, mine, ip)
    assert _strength(w.db, cand)[1] is False  # precondition: one unvalidated contact alone is not proposable

    result = _sweep(w, root)

    assert (result.claimed_domains, result.ips_checked, result.signals_recorded) == (1, 1, 1)
    (sig,) = _signals(cand.id)
    assert sig.anchor_kind == "claimed_candidate" and sig.anchor_candidate_id == claimed.id
    assert sig.matched_values == [ip] and ip in sig.quote and mine in sig.quote and cand.value in sig.quote
    fetch = w.db.get(EvidenceFetch, sig.evidence_id)
    blob = w.db.get(EvidenceBlob, fetch.sha256)
    body = json.loads(bytes(blob.content))
    assert body["rule"] == RULE and body["ip"] == ip and body["cidr"] == cand.value and body["claimed"] == mine
    strength, proposable = _strength(w.db, cand)
    assert proposable is True and strength != "strong"  # RIPE is never Strong; a Supporting pair is a lead


@pytest.mark.parametrize("verdict", ["shared", "historically_shared", "unknown"])
def test_a_verdict_other_than_dedicated_records_nothing(w, no_fetch, verdict):
    root = w.ours()
    mine = _dom("m")
    _claimed(w, root, mine)
    cand = _cidr(w, root, _net(2))
    _seed(w, mine, _v6(2), sharing=verdict)

    result = _sweep(w, root)

    assert (result.ips_checked, result.not_dedicated, result.signals_recorded) == (1, 1, 0)
    assert _signals(cand.id) == []


def test_no_ip_asset_and_no_claim_record_nothing_and_never_fetch(w, no_fetch):
    root = w.ours()
    a, b = _dom("a"), _dom("b")
    _claimed(w, root, a)
    _claimed(w, root, b)
    cand = _cidr(w, root, _net(3))
    _seed(w, a, _v6(3, 1), with_ip_asset=False)  # no ip_address asset: `_claimed_ips` yields nothing
    _seed(w, b, _v6(3, 2), with_claim=False)  # the asset exists, no verdict cached

    result = _sweep(w, root)

    assert (result.claimed_domains, result.ips_checked, result.no_claim, result.signals_recorded) == (2, 1, 1, 0)
    assert _signals(cand.id) == [] and no_fetch == []


def test_a_dedicated_ip_outside_every_candidate_is_counted_and_records_nothing(w, no_fetch):
    root = w.ours()
    mine = _dom("m")
    _claimed(w, root, mine)
    adjacent = _cidr(w, root, _net(5))  # the neighbouring /64 holds nothing of ours
    _seed(w, mine, _v6(4))

    result = _sweep(w, root)

    assert (result.ips_checked, result.outside_candidates, result.signals_recorded) == (1, 1, 0)
    assert _signals(adjacent.id) == []


def test_only_open_cidr_candidates_get_the_signal(w, no_fetch):
    root = w.ours()
    mine = _dom("m")
    _claimed(w, root, mine)
    ip = _v6(1)
    a = _cidr(w, root, _net(1))  # will be claimed
    b = _cidr(w, root, "2001:db8:278::/60")  # will be rejected
    c = _cidr(w, root, "2001:db8:278::/56")  # stays open
    _seed(w, mine, ip)
    first = _sweep(w, root)
    assert first.signals_recorded == 3  # all three were reached and are now proposable

    w.track_target(a.value)
    cd.claim(w.db, candidate_id=a.id, user=w.user())
    cd.reject(w.db, candidate_id=b.id, user=w.user(), reason="not ours")
    w.db.expire_all()
    assert (w.db.get(ScopeCandidate, a.id).status, w.db.get(ScopeCandidate, b.id).status) == ("claimed", "rejected")

    second = _sweep(w, root)

    assert (second.signals_recorded, second.signals_resighted) == (0, 1)  # only the open one was touched
    assert len(_signals(a.id)) == len(_signals(b.id)) == len(_signals(c.id)) == 1


def test_an_asn_candidate_of_the_same_handle_gets_nothing_while_the_cidr_does(w, no_fetch):
    root = w.ours()
    mine = _dom("m")
    _claimed(w, root, mine)
    cidr = _cidr(w, root, _net(6))
    asn = _record(w, root, "AS64500", "asn")
    assert (asn.rir, asn.rir_handle) == (cidr.rir, cidr.rir_handle)
    _seed(w, mine, _v6(6))

    result = _sweep(w, root)

    assert result.signals_recorded == 1
    assert len(_signals(cidr.id)) == 1 and _signals(asn.id) == []


def test_it_never_creates_a_candidate_and_ignores_another_roots_candidates(w, no_fetch):
    root, other = w.ours(), w.ours()
    mine = _dom("m")
    _claimed(w, root, mine)
    mine_c = _cidr(w, root, _net(7))
    theirs = _cidr(w, other, _net(7))  # the same prefix under another root
    _seed(w, mine, _v6(7))
    before = (_count(w, root), _count(w, other))

    result = _sweep(w, root)

    assert result.signals_recorded == 1 and len(_signals(mine_c.id)) == 1  # reached
    assert (_count(w, root), _count(w, other)) == before
    assert _signals(theirs.id) == []


def test_another_roots_containing_prefix_is_never_copied_into_this_root(w, no_fetch):
    # Only the other root holds a prefix containing the address: were the
    # root filter missing, record_signal would CREATE it under this root.
    root, other = w.ours(), w.ours()
    mine = _dom("x")
    _claimed(w, root, mine)
    theirs = _cidr(w, other, _net(8))
    _seed(w, mine, _v6(8))
    before = (_count(w, root), _count(w, other))

    result = _sweep(w, root)

    assert result.ips_checked == 1 and result.outside_candidates == 1  # reached, and matched nothing
    assert result.signals_recorded == 0
    assert (_count(w, root), _count(w, other)) == before
    assert _signals(theirs.id) == []


def test_an_open_domain_candidate_is_not_a_source(w, no_fetch):
    root = w.ours()
    claimed = _dom("c")
    _claimed(w, root, claimed)  # a claimed domain with no addresses: the sweep reaches the domain loop
    open_dom = w.candidate(root, value=_dom("o"))
    cand = _cidr(w, root, _net(8))
    _seed(w, open_dom.value, _v6(8))

    result = _sweep(w, root)

    assert result.claimed_domains == 1 and result.ips_checked == 0  # reached, and the open one was not read
    assert _signals(cand.id) == []


def test_a_rerun_resights_and_adds_no_rows(w, no_fetch):
    root = w.ours()
    mine = _dom("m")
    _claimed(w, root, mine)
    cand = _cidr(w, root, _net(9))
    _seed(w, mine, _v6(9))
    assert _sweep(w, root).signals_recorded == 1
    (first,) = _signals(cand.id)

    again = _sweep(w, root)

    assert (again.signals_recorded, again.signals_resighted) == (0, 1)
    (second,) = _signals(cand.id)
    assert second.id == first.id


# ── the runner ──────────────────────────────────────────────────────────────


def test_verify_after_claim_sweeps_the_root_after_the_rir_step_and_swallows_failure(w, monkeypatch):
    root = w.ours()
    claimed = _claimed(w, root, _dom("m"))
    order: list = []
    monkeypatch.setattr(runner, "reverse_ip_for_claimed", lambda cid: order.append("reverse"))
    monkeypatch.setattr(runner, "rir_for_claimed", lambda cid: order.append("rir"))
    monkeypatch.setattr(runner, "dedicated_ip_for_root", lambda rid: order.append(("dedicated", rid)))

    runner.verify_after_claim(claimed.id)
    assert order == ["reverse", "rir", ("dedicated", root.id)]

    order.clear()
    still_open = w.candidate(w.ours(), value=_dom("o"))  # its own root: no open pair for the claimed root to verify
    runner.verify_after_claim(still_open.id)  # not a claimed anchor: no root captured, no sweep
    assert order == ["reverse", "rir"]

    reached: list = []

    def boom(rid):
        reached.append(rid)
        raise RuntimeError("sweep exploded")

    monkeypatch.setattr(runner, "dedicated_ip_for_root", boom)
    assert runner.verify_after_claim(claimed.id).pairs_checked == 0  # did not raise
    assert reached == [root.id]


def test_a_failure_inside_the_generator_is_rolled_back_and_returns_the_empty_result(w, monkeypatch):
    root = w.ours()
    calls: list = []

    def boom(db, **kw):
        calls.append(kw)
        raise RuntimeError("generator exploded")

    monkeypatch.setattr(generators, "record_rir_dedicated_ip", boom)

    result = runner.dedicated_ip_for_root(root.id)

    assert calls and result == generators.RirDedicatedIpResult()


def test_dedicated_ip_for_root_commits_what_the_generator_flushed(w, no_fetch):
    root = w.ours()
    mine = _dom("m")
    _claimed(w, root, mine)
    cand = _cidr(w, root, _net(10))
    _seed(w, mine, _v6(10))

    result = runner.dedicated_ip_for_root(root.id)

    assert result.signals_recorded == 1 and len(_signals(cand.id)) == 1  # visible from another session


# ── the post-discovery hook ─────────────────────────────────────────────────


def test_the_hook_sweeps_each_touched_root_exactly_once(w, monkeypatch):
    r1, r2 = w.ours(), w.ours()
    a, b, c = _dom("a"), _dom("b"), _dom("c")
    _claimed(w, r1, a)
    _claimed(w, r1, b)
    _claimed(w, r2, c)
    reverse: list = []
    swept: list = []
    monkeypatch.setattr(runner, "reverse_ip_for_claimed", lambda cid: reverse.append(cid))
    monkeypatch.setattr(runner, "dedicated_ip_for_root", lambda rid: swept.append(rid))

    scan_executor._org_discovery_reverse_ip(w.db, {"domains": [a, b, c], "ip_ranges": []})

    assert len(reverse) == 3  # the per-candidate loop ran
    assert sorted(swept, key=str) == sorted([r1.id, r2.id], key=str) and len(swept) == 2

    swept.clear()
    scan_executor._org_discovery_reverse_ip(w.db, {"domains": [c], "ip_ranges": []})
    assert swept == [r2.id]
