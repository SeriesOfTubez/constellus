"""Prefix-first covering lookups and their flattening (planning#278 S3c3b1).

The transport (`rir_fetch.connector_get`) is replaced with a routing fake;
nothing leaves the process. Synthetic handles and documentation address space
only. Wire shapes copy live ARIN Whois-RWS and RIPE REST responses.

Run with:  scripts/test.sh app/tests/test_org_discovery_covering.py
"""

import copy
import ipaddress
import json

import pytest

from app.core.database import SessionLocal
from app.services.org_discovery import covering
from app.services.org_discovery import rir_fetch as rf
from app.services.org_discovery.reassignment import Reassigned, Registration, detect

CLAIMED = "192.0.2.0/24"
CLAIMED6 = "2001:db8::/32"
HOLDER = "EXAMPLE-ORG"
OTHER = "OTHER-ORG"
RIPE_HOLDER = "ORG-EXA1-RIPE"
RIPE_OTHER = "ORG-EXA2-RIPE"


class Resp:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return json.loads(json.dumps(self._payload))


class Router:
    """ARIN by path; RIPE by 'cov' / 'more' (the all-more flag)."""

    def __init__(self):
        self.routes: dict[str, object] = {}
        self.calls: list[str] = []

    def __call__(self, url, **kw):
        if url.startswith(rf.BASE_URLS["arin"]):
            key = url[len(rf.BASE_URLS["arin"]):]
        else:
            assert url.startswith(rf.BASE_URLS["ripe"])
            key = "ripe-more" if "all-more" in kw["params"]["flags"] else "ripe-cov"
        self.calls.append(key)
        item = self.routes.get(key)
        if isinstance(item, Exception):
            raise item
        if item is None:
            return Resp(404, None)
        if isinstance(item, Resp):
            return item
        return Resp(200, item)


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
        session.rollback()  # `get` only flushes, so nothing is left behind
        session.close()


# ── ARIN fixtures ────────────────────────────────────────────────────────────

def w(v):
    return {"$": v}


def many_or_one(items):
    return items[0] if len(items) == 1 else items


def ref(handle, cidr, upper=False):
    net = ipaddress.ip_network(cidr)
    start, end = str(net.network_address), str(net.broadcast_address)
    if upper:
        start, end = start.upper(), end.upper()
    return {"@startAddress": start, "@endAddress": end, "@handle": handle, "@name": "EXAMPLE-NET",
            "$": f"https://whois.arin.net/rest/net/{handle}"}


def nets_body(refs, exceeded=False):
    b = {"@xmlns": {"$": "x"}, "limitExceeded": {"@limit": "256", "$": "true" if exceeded else "false"}}
    if refs:
        b["netRef"] = many_or_one(refs)
    return {"nets": b}


def block(cidr):
    net = ipaddress.ip_network(cidr)
    return {"cidrLength": w(str(net.prefixlen)), "startAddress": w(str(net.network_address)),
            "endAddress": w(str(net.broadcast_address)), "type": w("DA")}


def net_body(handle, cidrs, holder=("orgRef", HOLDER)):
    kind, h = holder
    n = {"handle": w(handle), "netBlocks": {"netBlock": many_or_one([block(c) for c in cidrs])}}
    if kind is not None:
        n[kind] = {"@handle": h, "@name": h, "$": "u"}
    return {"net": n}


def less_path(p=CLAIMED):
    return f"cidr/{p}/less"


def more_path(p=CLAIMED):
    return f"cidr/{p}/more"


def arin_setup(router, *, less, more=None, nets=()):
    router.routes[less_path()] = less
    if more is not None:
        router.routes[more_path()] = more
    for h, body in nets:
        router.routes[f"net/{h}"] = body


def net_calls(router):
    return [c for c in router.calls if c.startswith("net/")]


# ── ARIN flatteners ──────────────────────────────────────────────────────────

def test_arin_net_registrations_org_customer_unknown():
    assert covering.arin_net_registrations(net_body("NET-A", [CLAIMED])) == (
        Registration(CLAIMED, "org", HOLDER),)
    assert covering.arin_net_registrations(net_body("NET-A", [CLAIMED], ("customerRef", "C-EXAMPLE"))) == (
        Registration(CLAIMED, "customer", "C-EXAMPLE"),)
    assert covering.arin_net_registrations(net_body("NET-A", [CLAIMED], (None, None))) == (
        Registration(CLAIMED, "unknown", None),)


def test_arin_net_registrations_several_blocks_and_ipv6():
    got = covering.arin_net_registrations(net_body("NET-A", ["198.51.100.0/24", "203.0.113.0/24"]))
    assert [r.prefix for r in got] == ["198.51.100.0/24", "203.0.113.0/24"]
    assert covering.arin_net_registrations(net_body("NET-6", [CLAIMED6])) == (Registration(CLAIMED6, "org", HOLDER),)


@pytest.mark.parametrize("body", [
    {}, {"net": {}}, {"net": {"netBlocks": {}}}, {"net": {"netBlocks": {"netBlock": []}}},
    {"net": {"netBlocks": {"netBlock": {"startAddress": w("999.0.0.0"), "cidrLength": w("24")}}}},
    {"net": {"netBlocks": {"netBlock": {"startAddress": w("192.0.2.1"), "cidrLength": w("24")}}}},
])
def test_arin_net_registrations_unparseable(body):
    with pytest.raises(ValueError):
        covering.arin_net_registrations(body)


# ── RIPE fixtures ────────────────────────────────────────────────────────────

def _a(k, v):
    return {"name": k, "value": v}


def robj(otype, pk, org=None, status="ASSIGNED PA", source="ripe", contact=None):
    attrs = [_a(otype, pk), _a("netname", "SYNTH")]
    if org:
        attrs.append(_a("org", org))
    if contact:
        attrs += [_a("admin-c", contact), _a("tech-c", contact)]
    attrs += [_a("status", status), _a("source", "RIPE")]
    return {"type": otype, "source": {"id": source}, "primary-key": {"attribute": [_a(otype, pk)]},
            "attributes": {"attribute": attrs}}


def rng(cidr):
    net = ipaddress.ip_network(cidr)
    return f"{net.network_address} - {net.broadcast_address}"


def inetnum(cidr, **kw):
    return robj("inetnum", rng(cidr), **kw)


def inet6num(cidr, **kw):
    return robj("inet6num", cidr, **kw)


def sbody(objs):
    return {"service": {}, "objects": {"object": objs}}


ROOT = robj("inetnum", "0.0.0.0 - 255.255.255.255", org="ORG-IANA1-RIPE", status="ALLOCATED UNSPECIFIED")
NOT_FOUND = {"errormessages": {"errormessage": [{"severity": "Error", "text": "ERROR:101: no entries found"}]}}


def ripe_setup(router, cov, more=None):
    router.routes["ripe-cov"] = cov
    if more is not None:
        router.routes["ripe-more"] = more


# ── RIPE flatteners ──────────────────────────────────────────────────────────

def test_ripe_registrations_org_and_no_org_and_contact_never_holder():
    body = sbody([inetnum(CLAIMED, org=RIPE_HOLDER), inetnum("198.51.100.0/24"),
                  inetnum("203.0.113.0/24", contact="EX1-RIPE")])
    assert covering.ripe_registrations(body) == (
        Registration(CLAIMED, "org", RIPE_HOLDER),
        Registration("198.51.100.0/24", "unknown", None),
        Registration("203.0.113.0/24", "unknown", None),
    )


def test_ripe_registrations_root_placeholder_skipped_and_ipv6():
    body = sbody([ROOT, inet6num(CLAIMED6, org=RIPE_HOLDER)])
    assert covering.ripe_registrations(body) == (Registration(CLAIMED6, "org", RIPE_HOLDER),)
    assert covering.ripe_registrations(sbody([ROOT])) == ()


def test_ripe_registrations_non_cidr_range_flattens():
    body = sbody([robj("inetnum", "192.0.2.0 - 192.0.2.130", org=RIPE_HOLDER)])
    got = covering.ripe_registrations(body)
    want = ipaddress.summarize_address_range(ipaddress.IPv4Address("192.0.2.0"), ipaddress.IPv4Address("192.0.2.130"))
    assert [r.prefix for r in got] == [str(n) for n in want]
    assert len(got) == 3 and all(r.holder_handle == RIPE_HOLDER for r in got)


@pytest.mark.parametrize("obj", [
    inetnum(CLAIMED, org=RIPE_HOLDER, source="arin"),
    robj("inetnum", "192.0.2.0-192.0.2.255", org=RIPE_HOLDER),
    robj("inetnum", "not a range"),
    {"type": "inetnum", "source": {"id": "ripe"}, "attributes": {"attribute": []}},
])
def test_ripe_registrations_unreadable_raises(obj):
    with pytest.raises(ValueError):
        covering.ripe_registrations(sbody([obj]))


def test_ripe_registrations_ignores_other_types():
    assert covering.ripe_registrations(sbody([robj("organisation", RIPE_HOLDER)])) == ()


# ── fetch_arin ───────────────────────────────────────────────────────────────

def run_arin(db, p=CLAIMED, budget=None):
    return covering.fetch_arin(db, p, budget or rf.Budget())


def test_arin_complete_same_holder(db, router):
    arin_setup(router, less=nets_body([ref("NET-A", CLAIMED)]), nets=[("NET-A", net_body("NET-A", [CLAIMED]))])
    c = run_arin(db)
    assert c.reason is None and c.answer.complete
    assert c.answer.registrations == (Registration(CLAIMED, "org", HOLDER),)
    assert router.calls == [less_path(), more_path(), "net/NET-A"]  # lone-dict netRef; more 404 tolerated
    assert [label for label, _ in c.sources] == [f"arin:{less_path()}", "arin:net/NET-A"]  # 404 omitted
    assert detect(CLAIMED, HOLDER, c.answer) == ()


def test_arin_whole_allocation_transferred(db, router):
    arin_setup(router, less=nets_body([ref("NET-A", CLAIMED)]), more=nets_body([ref("NET-A", CLAIMED)]),
               nets=[("NET-A", net_body("NET-A", [CLAIMED], ("orgRef", OTHER)))])
    c = run_arin(db)
    assert c.answer.complete
    assert net_calls(router) == ["net/NET-A"]  # exact match is in both lists, fetched once
    assert c.answer.registrations == (Registration(CLAIMED, "org", OTHER),)  # and flattened once
    assert [label for label, _ in c.sources].count("arin:net/NET-A") == 1
    assert detect(CLAIMED, HOLDER, c.answer) == (Reassigned(CLAIMED, "org", OTHER),)


def test_arin_customer_suballocation_and_list_netref(db, router):
    sub = "192.0.2.128/25"
    arin_setup(router,
               less=nets_body([ref("NET-WIDE", "192.0.0.0/16"), ref("NET-A", CLAIMED)]),  # list; smallest governs
               more=nets_body([ref("NET-A", CLAIMED), ref("NET-S1", sub)]),
               nets=[("NET-A", net_body("NET-A", [CLAIMED])),
                     ("NET-S1", net_body("NET-S1", [sub], ("customerRef", "C-EXAMPLE")))])
    c = run_arin(db)
    assert c.answer.complete
    assert "net/NET-WIDE" not in router.calls
    assert detect(CLAIMED, HOLDER, c.answer) == (Reassigned(sub, "customer", "C-EXAMPLE"),)


def test_arin_equal_smallest_covering_all_fetched(db, router):
    arin_setup(router, less=nets_body([ref("NET-A", CLAIMED), ref("NET-B", CLAIMED)]),
               nets=[("NET-A", net_body("NET-A", [CLAIMED])), ("NET-B", net_body("NET-B", [CLAIMED], ("orgRef", OTHER)))])
    c = run_arin(db)
    assert c.answer.complete and sorted(net_calls(router)) == ["net/NET-A", "net/NET-B"]
    assert detect(CLAIMED, HOLDER, c.answer) is None  # same prefix, different holders: ambiguous


def test_arin_ipv6_uppercase_refs(db, router):
    arin_setup(router, less=nets_body([ref("NET-6", CLAIMED6, upper=True)]),
               more=nets_body([ref("NET-6", CLAIMED6, upper=True)]),
               nets=[("NET-6", net_body("NET-6", [CLAIMED6]))])
    router.routes["cidr/2001:db8::/32/less"] = router.routes.pop(less_path())
    router.routes["cidr/2001:db8::/32/more"] = router.routes.pop(more_path())
    c = run_arin(db, CLAIMED6)
    assert c.answer.complete, c.reason
    assert detect(CLAIMED6, HOLDER, c.answer) == ()


def test_arin_bad_prefix(db, router):
    for bad in ("192.0.2.1/24", "nope", None):
        c = run_arin(db, bad)
        assert c.reason == "bad_prefix" and c.answer.complete is False and c.sources == ()
    assert router.calls == []


def test_arin_less_404_is_no_covering(db, router):
    c = run_arin(db)
    assert c.reason == "no_covering" and c.answer.complete is False
    assert router.calls == [less_path()]


def test_arin_less_without_refs_is_no_covering(db, router):
    arin_setup(router, less=nets_body([]))
    c = run_arin(db)
    assert c.reason == "no_covering" and c.answer.complete is False
    assert router.calls == [less_path(), more_path()]


@pytest.mark.parametrize("which", ["less", "more"])
def test_arin_truncated(db, router, which):
    ok = nets_body([ref("NET-A", CLAIMED)])
    cut = nets_body([ref("NET-A", CLAIMED)], exceeded=True)
    arin_setup(router, less=cut if which == "less" else ok, more=cut if which == "more" else ok,
               nets=[("NET-A", net_body("NET-A", [CLAIMED]))])
    c = run_arin(db)
    assert c.reason == "truncated" and c.answer.complete is False
    assert router.calls == [less_path(), more_path()]  # stopped before any net fetch


@pytest.mark.parametrize("less, more", [
    (nets_body([ref("NET-X", "198.51.100.0/24")]), None),  # does not contain the claimed prefix
    (nets_body([ref("NET-X", "192.0.2.0/26")]), None),  # inside it, not containing
    (nets_body([ref("NET-A", CLAIMED)]), nets_body([ref("NET-X", "203.0.113.0/26")])),  # more outside
    (nets_body([ref("NET-A", CLAIMED)]), nets_body([ref("NET-X", "192.0.0.0/16")])),  # more is wider
    (nets_body([ref("NET-6", CLAIMED6)]), None),  # wrong family
])
def test_arin_escaping(db, router, less, more):
    arin_setup(router, less=less, more=more)
    c = run_arin(db)
    assert c.reason == "escaping" and c.answer.complete is False
    assert router.calls[:2] == [less_path(), more_path()] and net_calls(router) == []


def test_arin_too_many(db, router):
    subs = [ref(f"NET-S{i}", f"2001:db8:278:{i:x}::/64") for i in range(covering.ARIN_MAX_NET_FETCHES + 1)]
    router.routes["cidr/2001:db8::/32/less"] = nets_body([ref("NET-6", CLAIMED6)])
    router.routes["cidr/2001:db8::/32/more"] = nets_body(subs)
    c = run_arin(db, CLAIMED6)
    assert c.reason == "too_many" and c.answer.complete is False
    assert router.calls == ["cidr/2001:db8::/32/less", "cidr/2001:db8::/32/more"]


def test_arin_exactly_the_cap_is_allowed(db, router):
    subs = [ref(f"NET-S{i}", f"2001:db8:278:{i:x}::/64") for i in range(covering.ARIN_MAX_NET_FETCHES - 1)]
    router.routes["cidr/2001:db8::/32/less"] = nets_body([ref("NET-6", CLAIMED6)])
    router.routes["cidr/2001:db8::/32/more"] = nets_body(subs)
    router.routes["net/NET-6"] = net_body("NET-6", [CLAIMED6])
    for i, s in enumerate(subs):
        router.routes[f"net/NET-S{i}"] = net_body(f"NET-S{i}", [f"2001:db8:278:{i:x}::/64"])
    budget = rf.Budget(limit=200)
    c = run_arin(db, CLAIMED6, budget)
    assert c.answer.complete, c.reason
    assert len(net_calls(router)) == covering.ARIN_MAX_NET_FETCHES


def test_arin_net_missing(db, router):
    arin_setup(router, less=nets_body([ref("NET-A", CLAIMED)]))
    c = run_arin(db)
    assert c.reason == "net_missing" and c.answer.complete is False
    assert net_calls(router) == ["net/NET-A"]


def test_arin_net_unparseable(db, router):
    arin_setup(router, less=nets_body([ref("NET-A", CLAIMED)]), nets=[("NET-A", {"net": {}})])
    c = run_arin(db)
    assert c.reason == "unparseable" and c.answer.complete is False
    assert net_calls(router) == ["net/NET-A"]


@pytest.mark.parametrize("bad_ref", [
    {"@startAddress": "999.0.0.0", "@endAddress": "192.0.2.255", "@handle": "NET-A"},
    {"@startAddress": "192.0.2.0", "@endAddress": "192.0.2.255", "@handle": "bad handle!"},
    {"@startAddress": "192.0.2.255", "@endAddress": "192.0.2.0", "@handle": "NET-A"},
])
def test_arin_ref_unparseable(db, router, bad_ref):
    arin_setup(router, less=nets_body([bad_ref]))
    c = run_arin(db)
    assert c.reason == "unparseable" and c.answer.complete is False
    assert net_calls(router) == []


def test_arin_nets_object_missing_is_unparseable(db, router):
    arin_setup(router, less={"unexpected": 1})
    c = run_arin(db)
    assert c.reason == "unparseable" and c.answer.complete is False
    assert router.calls == [less_path(), more_path()]


def test_arin_budget(db, router):
    arin_setup(router, less=nets_body([ref("NET-A", CLAIMED)]), nets=[("NET-A", net_body("NET-A", [CLAIMED]))])
    b = rf.Budget(limit=1)
    c = run_arin(db, budget=b)
    assert c.reason == "budget" and c.answer.complete is False
    assert router.calls == [less_path()] and b.used == 1


def test_arin_budget_in_net_phase(db, router):
    arin_setup(router, less=nets_body([ref("NET-A", CLAIMED)]), nets=[("NET-A", net_body("NET-A", [CLAIMED]))])
    c = run_arin(db, budget=rf.Budget(limit=2))
    assert c.reason == "budget" and c.answer.complete is False
    assert router.calls == [less_path(), more_path()]


@pytest.mark.parametrize("fail_on", ["less", "more", "net"])
def test_arin_fetch_error(db, router, fail_on):
    arin_setup(router, less=nets_body([ref("NET-A", CLAIMED)]), more=nets_body([]),
               nets=[("NET-A", net_body("NET-A", [CLAIMED]))])
    key = {"less": less_path(), "more": more_path(), "net": "net/NET-A"}[fail_on]
    router.routes[key] = Resp(500, {})
    c = run_arin(db)
    assert c.reason == "fetch_error" and c.answer.complete is False
    assert key in router.calls and router.calls[-1] == key


def test_arin_transport_exception_is_fetch_error(db, router):
    router.routes[less_path()] = RuntimeError("boom")
    c = run_arin(db)
    assert c.reason == "fetch_error" and c.answer.complete is False and router.calls == [less_path()]


# ── fetch_ripe ───────────────────────────────────────────────────────────────

def run_ripe(db, p=CLAIMED, budget=None):
    return covering.fetch_ripe(db, p, budget or rf.Budget())


def test_ripe_complete_same_holder(db, router):
    ripe_setup(router, sbody([inetnum(CLAIMED, org=RIPE_HOLDER)]))
    c = run_ripe(db)
    assert c.reason is None and c.answer.complete
    assert router.calls == ["ripe-cov", "ripe-more"]
    assert c.answer.registrations == (Registration(CLAIMED, "org", RIPE_HOLDER),)
    assert len(c.sources) == 1 and c.sources[0][0].startswith("ripe:search.json?")
    assert "flags=all-more" not in c.sources[0][0]
    assert detect(CLAIMED, RIPE_HOLDER, c.answer) == ()


def test_ripe_whole_allocation_transferred(db, router):
    ripe_setup(router, sbody([inetnum(CLAIMED, org=RIPE_OTHER)]))
    c = run_ripe(db)
    assert c.answer.complete
    assert detect(CLAIMED, RIPE_HOLDER, c.answer) == (Reassigned(CLAIMED, "org", RIPE_OTHER),)


def test_ripe_unregistered_remainder_via_root_placeholder(db, router):
    sub = "192.0.2.128/25"
    remainder = str(next(iter(ipaddress.ip_network(CLAIMED).address_exclude(ipaddress.ip_network(sub)))))
    ripe_setup(router, sbody([ROOT]), sbody([inetnum(sub, org=RIPE_HOLDER)]))
    c = run_ripe(db)
    assert c.answer.complete, c.reason
    assert [l for l, _ in c.sources if "all-more" in l] and len(c.sources) == 2
    assert detect(CLAIMED, RIPE_HOLDER, c.answer) == (Reassigned(remainder, "unregistered", None),)


def test_ripe_ipv6_and_more_specific_other_org(db, router):
    sub = "2001:db8:278:1::/64"
    ripe_setup(router, sbody([inet6num(CLAIMED6, org=RIPE_HOLDER)]), sbody([inet6num(sub, org=RIPE_OTHER)]))
    c = run_ripe(db, CLAIMED6)
    assert c.answer.complete, c.reason
    assert detect(CLAIMED6, RIPE_HOLDER, c.answer) == (Reassigned(sub, "org", RIPE_OTHER),)


def test_ripe_bad_prefix(db, router):
    c = run_ripe(db, "192.0.2.1/24")
    assert c.reason == "bad_prefix" and c.answer.complete is False and router.calls == []


@pytest.mark.parametrize("cov", [None, NOT_FOUND])
def test_ripe_no_covering(db, router, cov):
    ripe_setup(router, cov)
    c = run_ripe(db)
    assert c.reason == "no_covering" and c.answer.complete is False
    assert router.calls == ["ripe-cov"]


def test_ripe_all_more_error_on_200_is_fetch_error(db, router):
    ripe_setup(router, sbody([inetnum(CLAIMED, org=RIPE_HOLDER)]), NOT_FOUND)
    c = run_ripe(db)
    assert c.reason == "fetch_error" and c.answer.complete is False
    assert router.calls == ["ripe-cov", "ripe-more"]


def test_ripe_too_many(db, router):
    objs = [inet6num(f"2001:db8:278:{i:x}::/64", org=RIPE_HOLDER) for i in range(covering.RIPE_MAX_OBJECTS)]
    ripe_setup(router, sbody([inet6num(CLAIMED6, org=RIPE_HOLDER)]), sbody(objs))
    c = run_ripe(db, CLAIMED6)
    assert c.reason == "too_many" and c.answer.complete is False
    assert router.calls == ["ripe-cov", "ripe-more"]


def test_ripe_exactly_the_cap_is_allowed(db, router):
    objs = [inet6num(f"2001:db8:278:{i:x}::/64", org=RIPE_HOLDER) for i in range(covering.RIPE_MAX_OBJECTS - 1)]
    ripe_setup(router, sbody([inet6num(CLAIMED6, org=RIPE_HOLDER)]), sbody(objs))
    c = run_ripe(db, CLAIMED6)
    assert c.answer.complete, c.reason
    assert len(c.answer.registrations) == covering.RIPE_MAX_OBJECTS


@pytest.mark.parametrize("cov", [
    sbody([inetnum("198.51.100.0/24", org=RIPE_HOLDER)]),  # does not contain the claimed prefix
    sbody([inetnum("192.0.2.0/26", org=RIPE_HOLDER)]),  # inside it, not containing
    sbody([inet6num(CLAIMED6, org=RIPE_HOLDER)]),  # wrong object type for the query
])
def test_ripe_escaping_covering(db, router, cov):
    ripe_setup(router, cov)
    c = run_ripe(db)
    assert c.reason == "escaping" and c.answer.complete is False
    assert router.calls == ["ripe-cov", "ripe-more"]


@pytest.mark.parametrize("more_obj", [inetnum("203.0.113.0/26"), inetnum("192.0.0.0/16")])
def test_ripe_escaping_all_more(db, router, more_obj):
    ripe_setup(router, sbody([inetnum(CLAIMED, org=RIPE_HOLDER)]), sbody([more_obj]))
    c = run_ripe(db)
    assert c.reason == "escaping" and c.answer.complete is False
    assert router.calls == ["ripe-cov", "ripe-more"]


@pytest.mark.parametrize("cov", [sbody([]), sbody([inetnum(CLAIMED), inetnum("192.0.0.0/16")])])
def test_ripe_covering_must_hold_exactly_one_object(db, router, cov):
    ripe_setup(router, cov)
    c = run_ripe(db)
    assert c.reason == "unparseable" and c.answer.complete is False
    assert router.calls == ["ripe-cov", "ripe-more"]


def test_ripe_non_ripe_source_unparseable(db, router):
    ripe_setup(router, sbody([inetnum(CLAIMED, org=RIPE_HOLDER, source="arin")]))
    c = run_ripe(db)
    assert c.reason == "unparseable" and c.answer.complete is False
    assert router.calls == ["ripe-cov", "ripe-more"]


def test_ripe_unreadable_range_unparseable(db, router):
    ripe_setup(router, sbody([robj("inetnum", "garbage")]))
    c = run_ripe(db)
    assert c.reason == "unparseable" and c.answer.complete is False


def test_ripe_budget(db, router):
    ripe_setup(router, sbody([inetnum(CLAIMED, org=RIPE_HOLDER)]))
    b = rf.Budget(limit=1)
    c = run_ripe(db, budget=b)
    assert c.reason == "budget" and c.answer.complete is False
    assert router.calls == ["ripe-cov"] and b.used == 1


@pytest.mark.parametrize("fail_on", ["ripe-cov", "ripe-more"])
def test_ripe_fetch_error(db, router, fail_on):
    ripe_setup(router, sbody([inetnum(CLAIMED, org=RIPE_HOLDER)]), sbody([]))
    router.routes[fail_on] = Resp(503, {})
    c = run_ripe(db)
    assert c.reason == "fetch_error" and c.answer.complete is False
    assert router.calls[-1] == fail_on


def test_second_call_is_served_from_cache(db, router):
    ripe_setup(router, sbody([inetnum(CLAIMED, org=RIPE_HOLDER)]))
    b = rf.Budget()
    run_ripe(db, budget=b)
    first = len(router.calls)
    c = run_ripe(db, budget=b)
    assert c.answer.complete and len(router.calls) == first and b.cache_hits == 2
