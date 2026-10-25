"""ARIN collection + carve-out (planning#278 S3b1). Pure data, no signals.

The transport (`rir_fetch.connector_get`) is replaced by a router keyed on the
full URL, so the real `rir_fetch.get` and the real cache run. Documentation
space and synthetic handles only.

Run with:  scripts/test.sh app/tests/test_org_discovery_arin.py
"""

import dataclasses
import ipaddress

import pytest

from app.core.database import SessionLocal
from app.models.rir_lookup_cache import RirLookupCache
from app.services.org_discovery import arin
from app.services.org_discovery import rir_fetch as rf
from app.tests._org_world import hexid

BASE = rf.BASE_URLS["arin"]

# Documentation space, derived rather than written as literals: the address
# guard (test_docaddr_guard) keeps sub-/24 literals and interpolation out of
# the allocator's pool, and /24 networks are exempt from it.
A24 = ipaddress.ip_network("198.51.100.0/24")
B24 = ipaddress.ip_network("203.0.113.0/24")
A24S, B24S = str(A24), str(B24)
S25 = [str(n) for n in A24.subnets(new_prefix=25)]
S26 = [str(n) for n in A24.subnets(new_prefix=26)]
S27 = [str(n) for n in A24.subnets(new_prefix=27)]
S28 = [str(n) for n in A24.subnets(new_prefix=28)]


def rng(cidr):
    n = ipaddress.ip_network(cidr)
    return str(n.network_address), str(n.broadcast_address)


class Resp:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body

    def json(self):
        return self._body


class Router:
    def __init__(self):
        self.routes: dict[str, tuple[int, object]] = {}
        self.calls: list[str] = []

    def __call__(self, url, **kw):
        self.calls.append(url)
        status, body = self.routes.get(url, (404, None))
        return Resp(status, body)

    def add(self, path, body, status=200):
        self.routes[BASE + path] = (status, body)

    def count(self, path):
        return self.calls.count(BASE + path)


@pytest.fixture
def router(monkeypatch):
    r = Router()
    monkeypatch.setattr(rf, "connector_get", r)
    return r


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.query(RirLookupCache).filter(RirLookupCache.path.ilike("%arnt%")).delete(synchronize_session=False)
        session.commit()
        session.close()


@pytest.fixture
def t():
    return "ARNT" + hexid()[:6].upper()


def dom(t):
    return f"{t.lower()}.example.com"


# ── fixture builders (ARIN wire shape) ───────────────────────────────────────

def w(v):
    return {"$": v}


def many_or_one(items):
    return items[0] if len(items) == 1 else items


def pocs_body(handles, exceeded=False):
    refs = [{"@handle": h, "@name": h, "$": f"https://whois.arin.net/rest/poc/{h}"} for h in handles]
    body = {"limitExceeded": {"@limit": "256", "$": "true" if exceeded else "false"}}
    if refs:
        body["pocRef"] = many_or_one(refs)
    return {"pocs": body}


def poc_body(handle, emails, status="PV", wrapped=True):
    b = {"handle": w(handle), "isRoleAccount": w("N")}
    if emails:
        b["emails"] = {"email": many_or_one([w(e) for e in emails])}
    if status is not None:
        b["status"] = {"code": w(status) if wrapped else status, "description": w("x")}
    return {"poc": b}


def orgs_body(links):
    refs = [{"@handle": o, "@relPocFunction": f, "@relPocHandle": "P", "@name": o, "$": "u"} for o, f in links]
    return {"orgs": {"orgPocLinkRef": many_or_one(refs)}} if refs else {"orgs": {}}


def asns_body(asns, exceeded=False):
    refs = [{"@handle": a, "@name": a, "$": "u"} for a in asns]
    b = {"limitExceeded": {"@limit": "256", "$": "true" if exceeded else "false"}}
    if refs:
        b["asnRef"] = many_or_one(refs)
    return {"asns": b}


def nets_body(handles, exceeded=False):
    refs = [{"@handle": h, "@startAddress": str(A24.network_address), "@endAddress": str(A24.broadcast_address), "@name": h, "$": "u"} for h in handles]
    b = {"limitExceeded": {"@limit": "256", "$": "true" if exceeded else "false"}}
    if refs:
        b["netRef"] = many_or_one(refs)
    return {"nets": b}


def block(cidr, btype="DA"):
    net = ipaddress.ip_network(cidr)
    return {
        "cidrLength": w(str(net.prefixlen)), "startAddress": w(str(net.network_address)),
        "endAddress": w(str(net.broadcast_address)), "type": w(btype), "description": w(btype),
    }


def net_body(handle, cidrs, holder=("orgRef", None), parent=None, btype="DA"):
    kind, h = holder
    blocks = [block(c, btype) if isinstance(c, str) else c for c in cidrs]
    n = {
        "handle": w(handle),
        "netBlocks": {"netBlock": many_or_one(blocks)},
    }
    if kind is not None:
        n[kind] = {"@handle": h, "@name": h, "$": "u"}
    if parent:
        n["parentNetRef"] = {"@handle": parent, "@name": parent, "$": "u"}
    return {"net": n}


def children_body(refs, exceeded=False):
    """refs: list of (handle, start, end)."""
    b = {"limitExceeded": {"@limit": "256", "$": "true" if exceeded else "false"}}
    items = [{"@handle": h, "@startAddress": s, "@endAddress": e, "@name": h, "$": "u"} for h, s, e in refs]
    if items:
        b["netRef"] = many_or_one(items)
    return {"nets": b}


def setup_poc(router, t, emails=None, status="PV", org="ORG", funcs="AD", poc="POC1"):
    """One matched POC linked to one org. Returns (poc_handle, org_handle, domain)."""
    ph, oh = f"{t}-{poc}", f"{t}-{org}"
    d = dom(t)
    existing = router.routes.get(BASE + f"pocs;domain={d}")
    handles = [r["@handle"] for r in _refs(existing)] if existing else []
    router.add(f"pocs;domain={d}", pocs_body(handles + [ph]))
    router.add(f"poc/{ph}", poc_body(ph, emails or [f"a@{d}"], status))
    router.add(f"poc/{ph}/orgs", orgs_body([(oh, funcs)]))
    return ph, oh, d


def _refs(existing):
    ref = existing[1]["pocs"].get("pocRef", [])
    return [ref] if isinstance(ref, dict) else ref


def setup_org(router, oh, asns=(), nets=()):
    router.add(f"org/{oh}/asns", asns_body(list(asns)))
    router.add(f"org/{oh}/nets", nets_body(list(nets)))


def run(db, d, **kw):
    return arin.collect(db, d, rf.Budget(**kw))


# ── rule 1: exact domain ─────────────────────────────────────────────────────

def test_subdomain_and_apex_emails_match(db, router, t):
    d = dom(t)
    ph, oh, _ = setup_poc(router, t, [f"a@{d}"])
    p2, _, _ = setup_poc(router, t, [f"b@mail.{d}"], poc="POC2")
    setup_org(router, oh)
    res = run(db, d)
    assert [m.handle for m in res.matched] == [ph, p2]
    assert res.matched[1].email_domains == (f"mail.{d}",)
    assert res.pocs_not_exact == 0


@pytest.mark.parametrize("email", ["x@evil-{d}", "x@{d}.evil.net", "x@{D}.", "x@notmail{d}", "{d}", "x@@"])
def test_lookalike_emails_do_not_match(db, router, t, email):
    d = dom(t)
    ph, oh, _ = setup_poc(router, t, [email.format(d=d, D=d)])
    setup_org(router, oh)
    res = run(db, d)
    assert router.count(f"poc/{ph}") == 1  # reached: the POC was fetched, then rejected
    assert res.matched == () and res.pocs_not_exact == 1 and res.pocs_listed == 1
    assert router.count(f"poc/{ph}/orgs") == 0  # nothing fetched further
    assert res.orgs == {}


def test_email_case_is_folded(db, router, t):
    d = dom(t)
    ph, oh, _ = setup_poc(router, t, [f"X@{d.upper()}"])  # case is folded
    setup_org(router, oh)
    assert [m.handle for m in run(db, d).matched] == [ph]


def test_two_emails_one_matching(db, router, t):
    d = dom(t)
    ph, oh, _ = setup_poc(router, t, [f"a@evil-{d}", f"b@{d}"])
    setup_org(router, oh)
    res = run(db, d)
    assert [m.handle for m in res.matched] == [ph]
    assert res.matched[0].email_domains == (d,)


def test_last_at_sign_wins(db, router, t):
    d = dom(t)
    ph, oh, _ = setup_poc(router, t, [f"evil@{d}@other.net"])
    assert run(db, d).matched == ()
    assert router.count(f"poc/{ph}") == 1


# ── rule 2: validated ────────────────────────────────────────────────────────

@pytest.mark.parametrize("status, wrapped, expected", [
    ("PV", True, True), ("NV", True, False), (None, True, False), ("PV", False, False),
])
def test_validated_only_for_a_wrapped_pv(db, router, t, status, wrapped, expected):
    d = dom(t)
    ph, oh, _ = setup_poc(router, t)
    router.add(f"poc/{ph}", poc_body(ph, [f"a@{d}"], status, wrapped))
    setup_org(router, oh)
    res = run(db, d)
    assert len(res.matched) == 1  # reached: matched either way
    assert res.matched[0].validated is expected


def test_odd_status_shape_is_not_validated(db, router, t):
    d = dom(t)
    ph, oh, _ = setup_poc(router, t)
    router.add(f"poc/{ph}", {"poc": {"status": ["PV"], "emails": {"email": w(f"a@{d}")}}})
    setup_org(router, oh)
    assert run(db, d).matched[0].validated is False


# ── shapes: object vs list ───────────────────────────────────────────────────

@pytest.mark.parametrize("n", [1, 2])
def test_object_and_list_shapes_for_every_family(db, router, t, n):
    d = dom(t)
    pocs = [f"{t}-P{i}" for i in range(n)]
    orgs = [f"{t}-O{i}" for i in range(n)]
    router.add(f"pocs;domain={d}", pocs_body(pocs))
    for p in pocs:
        router.add(f"poc/{p}", poc_body(p, [f"a@{d}", f"b@{d}"][:n]))
        router.add(f"poc/{p}/orgs", orgs_body([(o, "AD") for o in orgs]))
    for i, o in enumerate(orgs):
        nets = [f"{t}-N{i}{j}" for j in range(n)]
        setup_org(router, o, [f"AS{64496 + i * 2 + j}" for j in range(n)], nets)
        for j, nh in enumerate(nets):
            k = (i * n + j) * 2
            blocks = [S28[k], S28[k + 1]][:n]
            router.add(f"net/{nh}", net_body(nh, blocks, ("orgRef", o)))
    res = run(db, d)
    assert len(res.matched) == n
    assert all(len(m.org_links) == n for m in res.matched)
    assert set(res.orgs) == set(orgs)
    for o in res.orgs.values():
        assert len(o.asns) == n and len(o.nets) == n
        assert all(len(nr.blocks) == n and nr.failed is None for nr in o.nets)
    assert res.pocs_listed == n


def test_org_functions_are_collected_per_org(db, router, t):
    d = dom(t)
    ph, oh, _ = setup_poc(router, t)
    router.add(f"poc/{ph}/orgs", orgs_body([(oh, "AD"), (oh, "T"), (oh, "AD")]))
    setup_org(router, oh)
    assert run(db, d).matched[0].org_links == ((oh, ("AD", "T")),)


def test_poc_with_no_orgs_is_still_matched(db, router, t):
    d = dom(t)
    ph, oh, _ = setup_poc(router, t)
    del router.routes[BASE + f"poc/{ph}/orgs"]  # 404
    res = run(db, d)
    assert router.count(f"poc/{ph}/orgs") == 1  # reached
    assert res.matched[0].org_links == () and res.orgs == {}
    router.add(f"poc/{ph}/orgs", orgs_body([]))
    router.calls.clear()
    db.query(RirLookupCache).filter(RirLookupCache.path.ilike("%arnt%")).delete(synchronize_session=False)
    assert run(db, d).matched[0].org_links == ()


# ── rule 4: memoisation, truncation, ASNs ────────────────────────────────────

def test_org_is_fetched_once_for_two_pocs(db, router, t):
    d = dom(t)
    p1, oh, _ = setup_poc(router, t)
    p2, _, _ = setup_poc(router, t, poc="POC2")
    setup_org(router, oh, ["AS64500"], [f"{t}-N1"])
    router.add(f"net/{t}-N1", net_body(f"{t}-N1", [A24S], ("orgRef", oh)))
    res = run(db, d)
    assert len(res.matched) == 2
    assert router.count(f"org/{oh}/nets") == 1 and router.count(f"org/{oh}/asns") == 1
    assert router.count(f"net/{t}-N1") == 1


def test_limit_exceeded_flags_and_items_still_processed(db, router, t):
    d = dom(t)
    ph, oh, _ = setup_poc(router, t)
    router.add(f"pocs;domain={d}", pocs_body([ph], exceeded=True))
    router.add(f"org/{oh}/asns", asns_body(["AS64500"], exceeded=True))
    router.add(f"org/{oh}/nets", nets_body([f"{t}-N1"], exceeded=True))
    router.add(f"net/{t}-N1", net_body(f"{t}-N1", [A24S], ("orgRef", oh)))
    res = run(db, d)
    o = res.orgs[oh]
    assert res.pocs_truncated and o.asns_truncated and o.nets_truncated
    assert len(res.matched) == 1 and o.asns == ("AS64500",)
    assert o.nets[0].pieces == (A24S,)


def test_flags_are_false_when_not_exceeded(db, router, t):
    ph, oh, d = setup_poc(router, t)
    setup_org(router, oh, ["AS64500"])
    res = run(db, d)
    assert not res.pocs_truncated
    assert not res.orgs[oh].asns_truncated and not res.orgs[oh].nets_truncated


def test_invalid_asns_are_counted_and_dropped(db, router, t):
    ph, oh, d = setup_poc(router, t)
    setup_org(router, oh, ["AS64500", "AS64512", "junk"])  # private, junk
    o = run(db, d).orgs[oh]
    assert o.asns == ("AS64500",) and o.invalid == 2


def test_org_with_nothing_still_appears(db, router, t):
    ph, oh, d = setup_poc(router, t)
    setup_org(router, oh)
    o = run(db, d).orgs[oh]
    assert o.asns == () and o.nets == ()


def test_invalid_handles_are_counted_and_skipped(db, router, t):
    d = dom(t)
    ph, oh, _ = setup_poc(router, t)
    router.add(f"pocs;domain={d}", pocs_body([ph, "bad/handle"]))
    router.add(f"poc/{ph}/orgs", orgs_body([(oh, "AD"), ("../x", "AD")]))
    router.add(f"org/{oh}/asns", asns_body([]))
    router.add(f"org/{oh}/nets", nets_body([f"{t}-N1", "a b"]))
    router.add(f"net/{t}-N1", net_body(f"{t}-N1", [A24S], ("orgRef", oh)))
    res = run(db, d)
    assert res.invalid_handles == 3
    assert len(res.matched) == 1 and len(res.orgs[oh].nets) == 1
    assert not any("bad" in c or ".." in c for c in router.calls)


# ── rule 5: held / nested / type ─────────────────────────────────────────────

def _one_org_with_nets(router, t, nets):
    ph, oh, d = setup_poc(router, t)
    setup_org(router, oh, [], list(nets))
    return oh, d


@pytest.mark.parametrize("holder", [("customerRef", "CUST-1"), ("orgRef", "OTHER-1"), (None, None)])
def test_not_held_is_skipped(db, router, t, holder):
    nh = f"{t}-N1"
    oh, d = _one_org_with_nets(router, t, [nh])
    router.add(f"net/{nh}", net_body(nh, [A24S], holder))
    res = run(db, d)
    assert router.count(f"net/{nh}") == 1  # reached
    o = res.orgs[oh]
    assert o.skipped_not_held == 1 and o.nets == ()
    # mutate the fixture: held by O -> processed
    router.add(f"net/{nh}", net_body(nh, [A24S], ("orgRef", oh)))
    db.query(RirLookupCache).filter(RirLookupCache.path.ilike("%arnt%")).delete(synchronize_session=False)
    o = run(db, d).orgs[oh]
    assert o.skipped_not_held == 0 and len(o.nets) == 1


def test_nested_own_net_is_skipped(db, router, t):
    parent, child = f"{t}-N1", f"{t}-N2"
    oh, d = _one_org_with_nets(router, t, [parent, child])
    router.add(f"net/{parent}", net_body(parent, [A24S], ("orgRef", oh)))
    router.add(f"net/{child}", net_body(child, [S26[0]], ("orgRef", oh), parent=parent))
    o = run(db, d).orgs[oh]
    assert router.count(f"net/{child}") == 1  # reached
    assert o.skipped_nested == 1 and [n.net_handle for n in o.nets] == [parent]


def test_parent_outside_the_orgs_list_is_not_nested(db, router, t):
    child = f"{t}-N2"
    oh, d = _one_org_with_nets(router, t, [child])
    router.add(f"net/{child}", net_body(child, [S26[0]], ("orgRef", oh), parent=f"{t}-NP"))
    o = run(db, d).orgs[oh]
    assert o.skipped_nested == 0 and [n.net_handle for n in o.nets] == [child]


@pytest.mark.parametrize("btype, skipped", [("DA", 0), ("A", 0), ("S", 0), ("R", 0), ("DS", 0), ("AF", 1), ("AR", 1), ("FX", 1)])
def test_block_type(db, router, t, btype, skipped):
    nh = f"{t}-N1"
    oh, d = _one_org_with_nets(router, t, [nh])
    router.add(f"net/{nh}", net_body(nh, [A24S], ("orgRef", oh), btype=btype))
    o = run(db, d).orgs[oh]
    assert o.skipped_type == skipped and len(o.nets) == 1 - skipped


def test_one_disallowed_block_skips_the_whole_net(db, router, t):
    nh = f"{t}-N1"
    oh, d = _one_org_with_nets(router, t, [nh])
    router.add(f"net/{nh}", net_body(nh, [block(S25[0]), block(S25[1], "AF")], ("orgRef", oh)))
    o = run(db, d).orgs[oh]
    assert o.skipped_type == 1 and o.nets == ()


def test_bad_block_fails_closed(db, router, t):
    nh = f"{t}-N1"
    oh, d = _one_org_with_nets(router, t, [nh])
    bad = block(A24S)
    bad["startAddress"] = w(str(A24.network_address + 7))  # host bits set: strict=True refuses
    router.add(f"net/{nh}", net_body(nh, [bad], ("orgRef", oh)))
    n = run(db, d).orgs[oh].nets[0]
    assert n.failed == "bad_block" and n.pieces == ()
    assert n.blocks[0].start_address == str(A24.network_address + 7) and n.blocks[0].cidr_length == "24"


# ── rule 6: carve-out ────────────────────────────────────────────────────────

PARENT = A24S


def carve(router, t, children, own_children=None, parent_cidrs=(PARENT,), grand=None):
    """children: list of (handle, cidr, holder). Returns (oh, d, parent_handle)."""
    nh = f"{t}-N1"
    oh, d = _one_org_with_nets(router, t, [nh])
    router.add(f"net/{nh}", net_body(nh, list(parent_cidrs), ("orgRef", oh)))
    refs = []
    for h, cidr, holder in children:
        n = ipaddress.ip_network(cidr)
        refs.append((h, str(n.network_address), str(n.broadcast_address)))
        router.add(f"net/{h}", net_body(h, [cidr], holder, parent=nh))
    router.add(f"net/{nh}/children", children_body(refs))
    return oh, d, nh


def result_net(db, oh, d):
    return run(db, d).orgs[oh].nets[0]


def test_carve_out_foreign_26(db, router, t):
    oh, d, _ = carve(router, t, [(f"{t}-C1", S26[1], ("orgRef", "OTHER-1"))])
    n = result_net(db, oh, d)
    assert n.failed is None
    assert n.pieces == (S26[0], S25[1])
    assert n.excluded == (arin.ExcludedChild(f"{t}-C1", "org", "OTHER-1", (S26[1],)),)


def test_mutated_child_owned_by_the_org_gives_the_whole_24(db, router, t):
    oh, d, _ = carve(router, t, [(f"{t}-C1", S26[1], ("orgRef", "PLACEHOLDER"))])
    router.add(f"net/{t}-C1", net_body(f"{t}-C1", [S26[1]], ("orgRef", oh), parent=f"{t}-N1"))
    router.add(f"net/{t}-C1/children", children_body([]))
    n = result_net(db, oh, d)
    assert router.count(f"net/{t}-C1/children") == 1  # the own child was walked
    assert n.pieces == (PARENT,) and n.excluded == ()


def test_customer_and_unknown_holders(db, router, t):
    oh, d, _ = carve(router, t, [
        (f"{t}-C1", S27[0], ("customerRef", "CUST-1")),
        (f"{t}-C2", S27[1], (None, None)),
    ])
    n = result_net(db, oh, d)
    assert [(e.holder_kind, e.holder_handle) for e in n.excluded] == [("customer", "CUST-1"), ("unknown", None)]
    assert n.pieces == (S26[1], S25[1])


def test_foreign_child_equal_to_parent_leaves_nothing(db, router, t):
    oh, d, _ = carve(router, t, [(f"{t}-C1", PARENT, ("orgRef", "OTHER-1"))])
    n = result_net(db, oh, d)
    assert n.pieces == () and n.failed is None and len(n.excluded) == 1


def test_foreign_child_containing_parent_leaves_nothing(db, router, t):
    supernet = str(ipaddress.ip_network(PARENT).supernet(new_prefix=16))  # computed: no public literal in the source
    oh, d, _ = carve(router, t, [(f"{t}-C1", supernet, ("orgRef", "OTHER-1"))])
    n = result_net(db, oh, d)
    assert n.pieces == () and n.failed is None


def test_own_child_with_foreign_grandchild(db, router, t):
    oh, d, nh = carve(router, t, [(f"{t}-C1", S25[0], ("orgRef", "PLACEHOLDER"))])
    router.add(f"net/{t}-C1", net_body(f"{t}-C1", [S25[0]], ("orgRef", oh), parent=nh))
    router.add(f"net/{t}-C1/children", children_body([(f"{t}-G1", *rng(S26[0]))]))
    router.add(f"net/{t}-G1", net_body(f"{t}-G1", [S26[0]], ("orgRef", "OTHER-1"), parent=f"{t}-C1"))
    n = result_net(db, oh, d)
    assert n.failed is None
    assert n.pieces == (S26[1], S25[1])
    assert [e.handle for e in n.excluded] == [f"{t}-G1"]


def _chain(router, t, levels):
    """Own child chain of `levels` levels under the parent, each walked."""
    oh, d, nh = carve(router, t, [(f"{t}-L1", S25[0], ("orgRef", "PLACEHOLDER"))])
    prev = nh
    for i in range(1, levels + 1):
        h = f"{t}-L{i}"
        router.add(f"net/{h}", net_body(h, [S25[0]], ("orgRef", oh), parent=prev))
        nxt = f"{t}-L{i + 1}"
        router.add(f"net/{h}/children", children_body([(nxt, *rng(S25[0]))]))
        prev = h
    return oh, d


def test_depth_beyond_max_is_too_deep(db, router, t):
    oh, d = _chain(router, t, arin.MAX_DEPTH + 1)
    n = result_net(db, oh, d)
    assert n.failed == "too_deep" and n.pieces == ()
    assert router.count(f"net/{t}-L{arin.MAX_DEPTH}/children") == 1  # reached the deepest allowed level


def test_depth_at_max_is_allowed(db, router, t):
    oh, d = _chain(router, t, arin.MAX_DEPTH)
    # the last chain child (L{MAX+1}) is foreign here: it has no route -> 404 -> unknown holder
    n = result_net(db, oh, d)
    assert n.failed is None
    assert n.excluded[0].holder_kind == "unknown"
    assert n.pieces == (S25[1],)


def test_children_truncated_fails_closed(db, router, t):
    oh, d, nh = carve(router, t, [(f"{t}-C1", S26[1], ("orgRef", "OTHER-1"))])
    router.add(f"net/{nh}/children", children_body([(f"{t}-C1", *rng(S26[1]))], exceeded=True))
    n = result_net(db, oh, d)
    assert n.failed == "children_truncated" and n.pieces == ()
    assert router.count(f"net/{nh}/children") == 1


def test_unparseable_foreign_range_is_bad_child(db, router, t):
    oh, d, nh = carve(router, t, [(f"{t}-C1", S26[1], ("orgRef", "OTHER-1"))])
    broken = net_body(f"{t}-C1", [S26[1]], ("orgRef", "OTHER-1"))
    broken["net"]["netBlocks"] = {}
    router.add(f"net/{t}-C1", broken)
    router.add(f"net/{nh}/children", children_body([(f"{t}-C1", "nope", "nope")]))
    n = result_net(db, oh, d)
    assert router.count(f"net/{t}-C1") == 1  # reached
    assert n.failed == "bad_child" and n.pieces == ()


def test_foreign_child_falls_back_to_the_ref_range(db, router, t):
    oh, d, nh = carve(router, t, [(f"{t}-C1", S26[1], ("orgRef", "OTHER-1"))])
    broken = net_body(f"{t}-C1", [S26[1]], ("orgRef", "OTHER-1"))
    del broken["net"]["netBlocks"]
    router.add(f"net/{t}-C1", broken)
    n = result_net(db, oh, d)
    assert n.failed is None and n.pieces == (S26[0], S25[1])


def test_too_many_pieces(db, router, t, monkeypatch):
    oh, d, _ = carve(router, t, [(f"{t}-C1", S26[1], ("orgRef", "OTHER-1"))])
    monkeypatch.setattr(arin, "MAX_PIECES", 1)
    n = result_net(db, oh, d)
    assert n.failed == "too_many_pieces" and n.pieces == ()
    # mutate: the same fixture at the limit of 2 passes
    monkeypatch.setattr(arin, "MAX_PIECES", 2)
    assert run(db, d).orgs[oh].nets[0].pieces == (S26[0], S25[1])


def test_ipv6_carve_out(db, router, t):
    oh, d, _ = carve(router, t, [(f"{t}-C1", "2001:db8:8000::/33", ("orgRef", "OTHER-1"))], parent_cidrs=("2001:db8::/32",))
    n = result_net(db, oh, d)
    assert n.failed is None and n.pieces == ("2001:db8::/33",)


def test_mixed_family_blocks_and_foreign(db, router, t):
    oh, d, _ = carve(router, t, [(f"{t}-C1", S26[1], ("orgRef", "OTHER-1"))],
                     parent_cidrs=(PARENT, "2001:db8::/32"))
    n = result_net(db, oh, d)
    assert n.pieces == (S26[0], S25[1], "2001:db8::/32")


def test_net_with_two_blocks(db, router, t):
    oh, d, _ = carve(router, t, [(f"{t}-C1", S26[1], ("orgRef", "OTHER-1"))],
                     parent_cidrs=(PARENT, B24S))
    n = result_net(db, oh, d)
    assert len(n.blocks) == 2
    assert n.pieces == (S26[0], S25[1], B24S)


def test_adjacent_pieces_are_collapsed(db, router, t):
    oh, d, _ = carve(router, t, [(f"{t}-C1", S25[0], ("orgRef", "OTHER-1"))],
                     parent_cidrs=(S25[0], S25[1]))
    assert result_net(db, oh, d).pieces == (S25[1],)


def test_no_children_gives_the_whole_block(db, router, t):
    oh, d, _ = carve(router, t, [])
    n = result_net(db, oh, d)
    assert router.count(f"net/{t}-N1/children") == 1
    assert n.pieces == (PARENT,) and n.excluded == ()


# ── rule 7: errors and budget ────────────────────────────────────────────────

def test_net_fetch_error_fails_that_net_only(db, router, t):
    n1, n2 = f"{t}-N1", f"{t}-N2"
    oh, d = _one_org_with_nets(router, t, [n1, n2])
    router.add(f"net/{n1}", {}, status=500)
    router.add(f"net/{n2}", net_body(n2, [B24S], ("orgRef", oh)))
    res = run(db, d)
    nets = {n.net_handle: n for n in res.orgs[oh].nets}
    assert nets[n1].failed == "fetch_failed" and nets[n1].pieces == ()
    assert nets[n2].failed is None and nets[n2].pieces == (B24S,)
    assert res.fetch_failed == 1 and not res.budget_exhausted


def test_children_fetch_error_fails_closed(db, router, t):
    oh, d, nh = carve(router, t, [])
    router.add(f"net/{nh}/children", {}, status=500)
    res = run(db, d)
    n = res.orgs[oh].nets[0]
    assert n.failed == "fetch_failed" and n.pieces == () and res.fetch_failed == 1


def test_child_net_fetch_error_fails_closed(db, router, t):
    oh, d, nh = carve(router, t, [(f"{t}-C1", S26[1], ("orgRef", "OTHER-1"))])
    router.add(f"net/{t}-C1", {}, status=500)
    res = run(db, d)
    assert res.orgs[oh].nets[0].failed == "fetch_failed" and res.fetch_failed == 1


def test_poc_and_org_fetch_errors_are_counted_and_the_run_continues(db, router, t):
    d = dom(t)
    p1, o1, _ = setup_poc(router, t, poc="POC1", org="ORG1")
    p2, o2, _ = setup_poc(router, t, poc="POC2", org="ORG2")
    p3, o3, _ = setup_poc(router, t, poc="POC3", org="ORG3")
    router.add(f"poc/{p1}", {}, status=500)
    router.add(f"org/{o2}/nets", {}, status=500)
    setup_org(router, o3, ["AS64500"])
    router.add(f"org/{o2}/asns", asns_body([]))
    res = run(db, d)
    assert res.fetch_failed == 2
    assert [m.handle for m in res.matched] == [p2, p3]  # p1 skipped, p2 matched though its org failed
    assert set(res.orgs) == {o3}


def test_pocs_listing_error(db, router, t):
    d = dom(t)
    router.add(f"pocs;domain={d}", {}, status=500)
    res = run(db, d)
    assert res.fetch_failed == 1 and res.matched == () and res.pocs_listed == 0


def test_pocs_listing_404_means_none(db, router, t):
    res = run(db, dom(t))
    assert len(router.calls) == 1  # reached
    assert res.matched == () and res.fetch_failed == 0


@pytest.mark.parametrize("limit", [1, 2, 3, 4, 5, 6, 7, 8])
def test_budget_stops_all_fetching(db, router, t, limit):
    nh, n2 = f"{t}-N1", f"{t}-N2"
    ph, oh, d = setup_poc(router, t)
    setup_org(router, oh, ["AS64500"], [nh, n2])
    router.add(f"net/{nh}", net_body(nh, [A24S], ("orgRef", oh)))
    router.add(f"net/{n2}", net_body(n2, [B24S], ("orgRef", oh)))
    router.add(f"net/{nh}/children", children_body([]))
    router.add(f"net/{n2}/children", children_body([]))
    # full run needs: pocs, poc, orgs, asns, nets, net1, children1, net2, children2 = 9
    res = run(db, d, limit=limit)
    assert res.budget_exhausted is True
    assert len(router.calls) == limit  # nothing after the budget ran out
    assert len(set(router.calls)) == limit
    full = run(db, d, limit=100)  # same cache: resumes without refetching what is cached
    assert full.budget_exhausted is False
    assert full.orgs[oh].nets[0].pieces == (A24S,)
    assert full.orgs[oh].nets[1].pieces == (B24S,)


def test_budget_exhausted_mid_net_marks_it_budget(db, router, t):
    nh = f"{t}-N1"
    ph, oh, d = setup_poc(router, t)
    setup_org(router, oh, [], [nh])
    router.add(f"net/{nh}", net_body(nh, [A24S], ("orgRef", oh)))
    res = run(db, d, limit=6)  # pocs, poc, orgs, asns, nets, net: the children fetch is the 7th
    assert res.budget_exhausted
    n = res.orgs[oh].nets[0]
    assert n.failed == "budget" and n.pieces == ()
    assert router.count(f"net/{nh}/children") == 0


def test_result_is_frozen_pure_data(db, router, t):
    ph, oh, d = setup_poc(router, t)
    setup_org(router, oh)
    res = run(db, d)
    with pytest.raises(dataclasses.FrozenInstanceError):
        res.domain = "x"
    with pytest.raises(dataclasses.FrozenInstanceError):
        res.matched[0].validated = False
