"""RIPE collection + one-level carve-out (planning#278 S3b2). Pure data, no signals.

The transport (`rir_fetch.connector_get`) is replaced by a router keyed on the
query it receives (the params dict), so the real `rir_fetch.ripe_get` and the
real cache run. Documentation space and synthetic handles only.

Run with:  scripts/test.sh app/tests/test_org_discovery_ripe.py
"""

import ipaddress

import pytest

from app.core.database import SessionLocal
from app.models.rir_lookup_cache import RirLookupCache
from app.services.org_discovery import ripe
from app.services.org_discovery import rir_fetch as rf

DOM = "example.com"
ORG = "ORG-EXA1-TEST"
ORG2 = "ORG-EXA2-TEST"
EX1 = "EX1-TEST"
RL1 = "RL1-TEST"
RL2 = "RL2-TEST"

# Documentation space, derived rather than written as literals (test_docaddr_guard).
A24 = ipaddress.ip_network("198.51.100.0/24")
B24 = ipaddress.ip_network("203.0.113.0/24")
S25 = list(A24.subnets(new_prefix=25))
V6 = ipaddress.ip_network("2001:db8::/32")


def irange(net):
    n = ipaddress.ip_network(net)
    return f"{n.network_address} - {n.broadcast_address}"


# ── transport ────────────────────────────────────────────────────────────────

class Resp:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body

    def json(self):
        return self._body


class Router:
    def __init__(self):
        self.routes: dict[tuple, tuple[int, object]] = {}
        self.calls: list[tuple] = []

    @staticmethod
    def key(url, params):
        if url.endswith("fulltextsearch/select"):
            return ("ft", int(params["start"][0]))
        qs = params["query-string"][0]
        if "one-more" in params.get("flags", []):
            return ("om", qs)
        return ("inv", qs, "org" if params["inverse-attribute"] == ["org"] else "contact")

    def __call__(self, url, **kw):
        k = self.key(url, kw["params"])
        self.calls.append(k)
        status, body = self.routes.get(k, (404, None))
        return Resp(status, body)

    def ft(self, docs, page=0, num=None, status=200):
        n = len(docs) if num is None else num
        self.routes[("ft", page * rf.RIPE_FULLTEXT_ROWS)] = (status, ft_body(docs, n, page * rf.RIPE_FULLTEXT_ROWS))

    def inv(self, handle, objs, kind="contact", status=200, errors=None):
        self.routes[("inv", handle, kind)] = (status, search_body(objs, errors))

    def om(self, key, objs, status=200, errors=None):
        self.routes[("om", key)] = (status, search_body(objs, errors))

    def count(self, kind):
        return len([c for c in self.calls if c[0] == kind])


@pytest.fixture
def router(monkeypatch):
    r = Router()
    monkeypatch.setattr(rf, "connector_get", r)
    return r


def _clean(session):
    session.query(RirLookupCache).filter(RirLookupCache.rir == "ripe").delete(synchronize_session=False)
    session.commit()


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        _clean(session)
        yield session
    finally:
        session.rollback()
        _clean(session)
        session.close()


# ── fixture builders (RIPE wire shape) ───────────────────────────────────────

def ft_doc(handle, otype="role", emails=(), abuse=()):
    strs = [("primary-key", "123"), ("object-type", otype), ("lookup-key", handle)]
    strs += [("e-mail", e) for e in emails] + [("abuse-mailbox", a) for a in abuse]
    return {"doc": {"strs": [{"str": {"name": k, "value": v}} for k, v in strs]}}


def ft_body(docs, num, start=0):
    return {"result": {"name": "response", "numFound": num, "start": start, "docs": docs}}


def _attr(k, v, ref=None):
    a = {"name": k, "value": v}
    if ref:
        a["referenced-type"] = ref
        a["link"] = {"type": "locator", "href": "x"}
    return a


def obj(otype, pk, attrs, source="ripe"):
    return {
        "type": otype, "link": {"type": "locator", "href": "x"}, "source": {"id": source},
        "primary-key": {"attribute": [{"name": otype, "value": pk}]},
        "attributes": {"attribute": [_attr(otype, pk)] + attrs + [_attr("source", "RIPE")]},
    }


DEFAULT_STATUS = {"inetnum": "ASSIGNED PA", "inet6num": "ASSIGNED", "aut-num": "ASSIGNED"}


def res(otype, pk, status=None, org=None, admin=(), tech=(), source="ripe"):
    attrs = [_attr("netname", "SYNTH")]
    if org:
        attrs.append(_attr("org", org, "organisation"))
    attrs += [_attr("admin-c", h, "role") for h in admin] + [_attr("tech-c", h, "role") for h in tech]
    attrs.append(_attr("status", status or DEFAULT_STATUS[otype]))
    return obj(otype, pk, attrs, source)


def net4(cidr, **kw):
    return res("inetnum", irange(cidr), **kw)


def organisation(handle, source="ripe"):
    return obj("organisation", handle, [_attr("org-type", "OTHER")], source)


def search_body(objs, errors=None):
    b = {"service": {}, "parameters": {}, "objects": {"object": objs}, "terms-and-conditions": {}, "version": {}}
    if errors:
        b["errormessages"] = {"errormessage": [{"severity": s, "text": "x"} for s in errors]}
    return b


def setup_contact(router, handle=RL1, otype="role", emails=(f"noc@{DOM}",), objs=()):
    router.ft([ft_doc(handle, otype, emails)])
    if otype == "organisation":
        router.inv(handle, list(objs), kind="org")
    else:
        router.inv(handle, list(objs))


def run(db, domain=DOM, **kw):
    return ripe.collect(db, domain, rf.Budget(**kw))


def only(c):
    assert len(c.resources) == 1
    return c.resources[0]


# ── full text + exact re-check ───────────────────────────────────────────────

def test_loose_hit_is_filtered_and_reached(db, router):
    router.ft([ft_doc(RL1, "role", [f"noc@{DOM}"]), ft_doc(RL2, "role", ["noc@fabrikam.com"])])
    router.inv(RL1, [net4(A24, admin=[RL1])])
    router.inv(RL2, [net4(B24, admin=[RL2])])
    c = run(db)
    assert [m.handle for m in c.matched] == [RL1]
    assert c.contacts_not_exact == 1 and c.docs_seen == 2 and c.docs_found == 2
    assert ("inv", RL1, "contact") in router.calls
    assert ("inv", RL2, "contact") not in router.calls
    assert [r.primary_key for r in c.resources] == [irange(A24)]


def test_comment_is_cut_and_still_matches(db, router):
    setup_contact(router, emails=[f"noc@{DOM} # unknown e-mail address"])
    c = run(db)
    assert [m.handle for m in c.matched] == [RL1]
    assert c.matched[0].email_domains == (DOM,)


def test_address_only_inside_the_comment_does_not_match(db, router):
    router.ft([ft_doc(RL1, "role", [f"x@fabrikam.com # was noc@{DOM}"])])
    c = run(db)
    assert c.matched == () and c.contacts_not_exact == 1 and c.docs_seen == 1
    assert router.count("inv") == 0


@pytest.mark.parametrize("addr", [f"noc@{DOM}.", f"noc@bad{DOM}", f"noc@{DOM}.evil.org", "noc", f"{DOM}"])
def test_non_matching_addresses(db, router, addr):
    router.ft([ft_doc(RL1, "role", [addr])])
    c = run(db)
    assert c.matched == () and c.contacts_not_exact == 1
    assert router.count("inv") == 0


def test_subdomain_uppercase_and_abuse_mailbox_match(db, router):
    router.ft([ft_doc(RL1, "role", ["a@MAIL.Example.COM"], abuse=[f"abuse@{DOM}"])])
    router.inv(RL1, [])
    c = run(db)
    assert c.matched == (ripe.MatchedContact(RL1, "role", (DOM, f"mail.{DOM}")),)


def test_abuse_mailbox_alone_on_a_person_matches(db, router):
    router.ft([ft_doc(RL2, "person", [], abuse=["x@sub." + DOM])])
    router.inv(RL2, [])
    assert [m.handle for m in run(db).matched] == [RL2]


def test_other_object_types_are_ignored(db, router):
    router.ft([ft_doc("MNT1-TEST", "mntner", [f"a@{DOM}"]), ft_doc("1", "inetnum", [f"a@{DOM}"]),
               ft_doc(EX1, "person", [f"a@{DOM}"])])
    router.inv(EX1, [])
    c = run(db)
    assert c.docs_other_type == 2 and [m.handle for m in c.matched] == [EX1]
    assert ("inv", "MNT1-TEST", "contact") not in router.calls and router.count("inv") == 1


def test_matched_contacts_dedupe_by_handle_and_merge_domains(db, router):
    router.ft([ft_doc(RL1, "role", [f"a@{DOM}"]), ft_doc(RL1, "role", [f"a@x.{DOM}"])])
    router.inv(RL1, [])
    c = run(db)
    assert c.matched == (ripe.MatchedContact(RL1, "role", (DOM, f"x.{DOM}")),)
    assert router.count("inv") == 1


def test_invalid_lookup_key_is_counted_and_skipped(db, router):
    router.ft([ft_doc("bad handle!", "role", [f"a@{DOM}"])])
    c = run(db)
    assert c.invalid_handles == 1 and c.matched == () and c.docs_seen == 1
    assert router.count("inv") == 0


def test_paging_stops_at_numfound(db, router):
    router.ft([ft_doc(RL1, "role", [f"a@{DOM}"])], page=0, num=150)
    router.ft([ft_doc(RL2, "role", [f"a@{DOM}"])], page=1, num=150)
    router.inv(RL1, [])
    router.inv(RL2, [])
    c = run(db)
    assert router.count("ft") == 2 and not c.fulltext_truncated and c.docs_found == 150
    assert [m.handle for m in c.matched] == [RL1, RL2]


def test_single_page_when_everything_fits(db, router):
    router.ft([ft_doc(RL1, "role", [f"a@{DOM}"])], num=rf.RIPE_FULLTEXT_ROWS)
    router.inv(RL1, [])
    c = run(db)
    assert router.count("ft") == 1 and not c.fulltext_truncated


def test_paging_stops_at_page_cap_and_reports_truncation(db, router):
    for page in range(rf.RIPE_MAX_FULLTEXT_PAGES):
        router.ft([ft_doc(f"RL{page + 1}-TEST", "role", [f"a@{DOM}"])], page=page, num=1000)
        router.inv(f"RL{page + 1}-TEST", [])
    c = run(db)
    assert router.count("ft") == rf.RIPE_MAX_FULLTEXT_PAGES
    assert c.fulltext_truncated and c.docs_found == 1000 and c.docs_seen == rf.RIPE_MAX_FULLTEXT_PAGES
    assert len(c.matched) == rf.RIPE_MAX_FULLTEXT_PAGES  # what was seen is still processed


def test_exactly_at_the_cap_is_not_truncated(db, router):
    cap = rf.RIPE_MAX_FULLTEXT_PAGES * rf.RIPE_FULLTEXT_ROWS
    for page in range(rf.RIPE_MAX_FULLTEXT_PAGES):
        router.ft([], page=page, num=cap)
    c = run(db)
    assert router.count("ft") == rf.RIPE_MAX_FULLTEXT_PAGES and not c.fulltext_truncated


def test_fulltext_failure_is_counted(db, router):
    router.ft([], status=500)
    c = run(db)
    assert router.count("ft") == 1 and c.fetch_failed == 1 and c.matched == () and c.resources == ()


def test_wrong_shaped_bodies_are_empty(db, router):
    router.routes[("ft", 0)] = (200, {"result": ["x"]})
    assert run(db).docs_seen == 0
    _clean(db)
    router.routes[("ft", 0)] = (200, ft_body([{"doc": "x"}, "y", {"doc": {"strs": "z"}}], 3))
    c = run(db)
    assert c.docs_seen == 2 and c.docs_other_type == 2  # non-dict entries are dropped
    _clean(db)
    setup_contact(router)
    router.routes[("inv", RL1, "contact")] = (200, {"objects": "nope"})
    c = run(db)
    assert c.matched and c.resources == ()


# ── resources, holder ────────────────────────────────────────────────────────

def test_org_held_resource(db, router):
    setup_contact(router, objs=[net4(A24, org=ORG, admin=[RL1])])
    router.om(irange(A24), [])
    r = only(run(db))
    assert (r.holder_kind, r.holder, r.via, r.via_attributes) == ("org", ORG, (RL1,), ("admin-c",))
    assert r.object_type == "inetnum" and r.status == "ASSIGNED PA" and r.primary_key == irange(A24)
    assert r.pieces == (str(A24),) and r.failed is None and r.excluded == ()
    assert router.count("om") == 1


def test_contact_held_resource_has_smallest_contact(db, router):
    router.ft([ft_doc(RL2, "role", [f"a@{DOM}"]), ft_doc(RL1, "role", [f"a@{DOM}"])])
    shared = net4(A24, admin=[RL1], tech=[RL2])
    router.inv(RL1, [shared])
    router.inv(RL2, [shared])
    router.om(irange(A24), [])
    r = only(run(db))
    assert (r.holder_kind, r.holder, r.via) == ("contact", RL1, (RL1, RL2))
    assert r.via_attributes == ("admin-c", "tech-c")


def test_org_attribute_wins_over_contacts(db, router):
    router.ft([ft_doc(RL1, "role", [f"a@{DOM}"])])
    router.inv(RL1, [net4(A24, org=ORG2, admin=[RL1])])
    router.om(irange(A24), [])
    r = only(run(db))
    assert (r.holder_kind, r.holder) == ("org", ORG2)


def test_invalid_org_attribute_skips_the_resource(db, router):
    setup_contact(router, objs=[net4(A24, org="bad org!", admin=[RL1])])
    c = run(db)
    assert c.resources == () and c.invalid_handles == 1
    assert router.count("inv") == 1 and router.count("om") == 0


def test_role_leads_to_organisation_followed_once(db, router):
    router.ft([ft_doc(RL1, "role", [f"a@{DOM}"]), ft_doc(RL2, "role", [f"b@{DOM}"])])
    for h in (RL1, RL2):
        router.inv(h, [organisation(ORG), net4(B24, admin=[h])])
    router.inv(ORG, [net4(A24, org=ORG)], kind="org")
    router.om(irange(A24), [])
    router.om(irange(B24), [])
    c = run(db)
    assert router.calls.count(("inv", ORG, "org")) == 1
    assert c.orgs_followed == 1
    by = {r.primary_key: r for r in c.resources}
    assert by[irange(A24)].via == (RL1, RL2) and by[irange(A24)].via_attributes == ("org",)
    assert by[irange(A24)].holder == ORG
    assert by[irange(B24)].holder_kind == "contact" and by[irange(B24)].holder == RL1


def test_org_followed_from_role_uses_org_inverse_params(db, router):
    setup_contact(router, objs=[organisation(ORG)])
    router.inv(ORG, [], kind="org")
    run(db)
    assert ("inv", ORG, "org") in router.calls


def test_matched_organisation_uses_org_inverse(db, router):
    setup_contact(router, handle=ORG, otype="organisation", objs=[res("aut-num", "AS64500", org=ORG)])
    c = run(db)
    r = only(c)
    assert r.asn == "AS64500" and r.via == (ORG,) and r.holder == ORG
    assert router.calls[-1] == ("inv", ORG, "org") and router.count("om") == 0


def test_404_holder_holds_nothing_and_is_not_an_error(db, router):
    router.ft([ft_doc(RL1, "role", [f"a@{DOM}"])])  # no inverse route -> 404
    c = run(db)
    assert router.count("inv") == 1
    assert c.resources == () and c.fetch_failed == 0 and [m.handle for m in c.matched] == [RL1]


def test_error_severity_is_a_fetch_failure(db, router):
    setup_contact(router, objs=[net4(A24, admin=[RL1])])
    router.inv(RL1, [net4(A24, admin=[RL1])], errors=["Warning", "Error"])
    c = run(db)
    assert router.count("inv") == 1 and c.fetch_failed == 1 and c.resources == ()


def test_warning_and_info_are_not_failures(db, router):
    setup_contact(router)
    router.inv(RL1, [net4(A24, admin=[RL1])], errors=["Warning", "Info"])
    router.om(irange(A24), [])
    c = run(db)
    assert c.fetch_failed == 0 and len(c.resources) == 1


def test_http_error_on_lookup_is_counted_and_run_continues(db, router):
    router.ft([ft_doc(RL1, "role", [f"a@{DOM}"]), ft_doc(RL2, "role", [f"b@{DOM}"])])
    router.inv(RL1, [], status=500)
    router.inv(RL2, [net4(A24, admin=[RL2])])
    router.om(irange(A24), [])
    c = run(db)
    assert c.fetch_failed == 1 and len(c.resources) == 1 and router.count("inv") == 2


def test_non_ripe_source_is_skipped(db, router):
    setup_contact(router, objs=[net4(A24, admin=[RL1], source="apnic"), net4(B24, admin=[RL1])])
    router.om(irange(B24), [])
    c = run(db)
    assert c.skipped_source == 1
    assert [r.primary_key for r in c.resources] == [irange(B24)]
    assert ("om", irange(A24)) not in router.calls


def test_organisation_with_other_source_is_not_followed(db, router):
    setup_contact(router, objs=[organisation(ORG, source="apnic")])
    router.inv(ORG, [], kind="org")
    c = run(db)
    assert c.skipped_source == 1 and c.orgs_followed == 0 and router.count("inv") == 1


def test_unrequested_type_is_ignored(db, router):
    setup_contact(router, objs=[obj("mntner", "MNT-TEST", []), net4(A24, admin=[RL1])])
    router.om(irange(A24), [])
    c = run(db)
    assert len(c.resources) == 1 and c.skipped_source == 0


def test_status_allowlist(db, router):
    objs = [net4(A24, admin=[RL1], status="NOT-SET"), net4(B24, admin=[RL1], status="aSSIGNED pa"),
            net4(S25[0], admin=[RL1], status="ASSIGNED PA"),
            res("inet6num", str(V6), admin=[RL1], status="ASSIGNED PA"),
            res("aut-num", "AS64501", admin=[RL1], status="OTHER")]
    setup_contact(router, objs=objs)
    router.om(irange(S25[0]), [])
    c = run(db)
    assert c.skipped_status == 4
    assert [r.primary_key for r in c.resources] == [irange(S25[0])]
    assert router.count("om") == 1


@pytest.mark.parametrize("otype,pk,status", [
    ("inetnum", irange(A24), "LEGACY"), ("inetnum", irange(A24), "SUB-ALLOCATED PA"),
    ("inet6num", str(V6), "ALLOCATED-BY-RIR"), ("aut-num", "AS64502", "LEGACY"),
])
def test_allowed_statuses_are_proposed(db, router, otype, pk, status):
    setup_contact(router, objs=[res(otype, pk, admin=[RL1], status=status)])
    router.om(pk, [])
    assert len(run(db).resources) == 1


def test_aut_num_is_normalised_and_has_no_carve_out(db, router):
    setup_contact(router, objs=[res("aut-num", "AS64500", admin=[RL1]), res("aut-num", "AS64512", admin=[RL1])])
    c = run(db)
    assert [r.asn for r in c.resources] == ["AS64500"] and c.invalid == 1
    assert only(c).pieces == () and only(c).failed is None
    assert router.count("om") == 0 and router.count("inv") == 1


def test_resources_are_deduplicated_and_sorted(db, router):
    router.ft([ft_doc(RL1, "role", [f"a@{DOM}"]), ft_doc(RL2, "role", [f"a@{DOM}"])])
    for h in (RL1, RL2):
        router.inv(h, [net4(B24, admin=[h]), res("aut-num", "AS64501", admin=[h]), net4(A24, admin=[h]),
                       res("inet6num", str(V6), admin=[h])])
    for pk in (irange(A24), irange(B24), str(V6)):
        router.om(pk, [])
    c = run(db)
    assert [(r.object_type, r.primary_key) for r in c.resources] == [
        ("aut-num", "AS64501"), ("inet6num", str(V6)), ("inetnum", irange(A24)), ("inetnum", irange(B24))]
    assert all(r.via == (RL1, RL2) for r in c.resources)
    assert router.count("om") == 3


# ── ranges ───────────────────────────────────────────────────────────────────

def test_non_cidr_range_is_summarised(db, router):
    first = A24.network_address + 10
    last = A24.network_address + 20
    pk = f"{first} - {last}"
    setup_contact(router, objs=[res("inetnum", pk, admin=[RL1])])
    router.om(pk, [])
    r = only(run(db))
    expected = [str(n) for n in ipaddress.collapse_addresses(ipaddress.summarize_address_range(first, last))]
    assert len(expected) > 1 and list(r.pieces) == expected and r.primary_key == pk


def test_inet6num_prefix(db, router):
    v6 = next(V6.subnets(new_prefix=48))
    setup_contact(router, objs=[res("inet6num", str(v6), admin=[RL1])])
    router.om(str(v6), [])
    assert only(run(db)).pieces == (str(v6),)


@pytest.mark.parametrize("otype,pk", [
    ("inetnum", "not a range"), ("inetnum", f"{A24.broadcast_address} - {A24.network_address}"),
    ("inet6num", f"{V6.network_address + 1}/32"), ("inet6num", "garbage"),
])
def test_unparseable_range_fails_without_a_lookup(db, router, otype, pk):
    setup_contact(router, objs=[res(otype, pk, admin=[RL1])])
    r = only(run(db))
    assert r.failed == "bad_range" and r.pieces == () and router.count("om") == 0


# ── carve-out ────────────────────────────────────────────────────────────────

def test_no_children_is_the_whole_block(db, router):
    setup_contact(router, objs=[net4(A24, org=ORG, admin=[RL1])])
    router.om(irange(A24), [net4(A24, org=ORG)])  # only the parent itself comes back
    r = only(run(db))
    assert r.pieces == (str(A24),) and r.excluded == () and r.nested == () and r.failed is None


def test_foreign_child_is_carved_out_and_recorded(db, router):
    setup_contact(router, objs=[net4(A24, org=ORG, admin=[RL1])])
    router.om(irange(A24), [net4(A24, org=ORG), net4(S25[1], org=ORG2)])
    r = only(run(db))
    assert r.pieces == (str(S25[0]),)
    assert r.excluded == (ripe.ExcludedChild(irange(S25[1]), "org", ORG2, (str(S25[1]),)),)
    assert r.nested == () and r.nested_not_collected == 0


def test_child_without_org_is_unknown_holder(db, router):
    setup_contact(router, objs=[net4(A24, org=ORG, admin=[RL1])])
    router.om(irange(A24), [net4(S25[1])])
    r = only(run(db))
    assert r.excluded == (ripe.ExcludedChild(irange(S25[1]), "unknown", None, (str(S25[1]),)),)
    assert r.pieces == (str(S25[0]),)


def test_every_child_is_subtracted(db, router):
    kids = list(S25[0].subnets(new_prefix=26))
    setup_contact(router, objs=[net4(A24, org=ORG, admin=[RL1])])
    router.om(irange(A24), [net4(k, org=ORG2) for k in kids] + [net4(S25[1], org=ORG2)])
    r = only(run(db))
    assert r.pieces == () and len(r.excluded) == 3 and r.failed is None


def test_same_holder_child_in_set_is_nested_and_proposed_on_its_own(db, router):
    setup_contact(router, objs=[net4(A24, org=ORG, admin=[RL1]), net4(S25[1], org=ORG, admin=[RL1])])
    router.om(irange(A24), [net4(A24, org=ORG), net4(S25[1], org=ORG)])
    router.om(irange(S25[1]), [])
    c = run(db)
    parent, child = sorted(c.resources, key=lambda r: r.primary_key)
    assert parent.primary_key == irange(A24) and child.primary_key == irange(S25[1])
    assert parent.pieces == (str(S25[0]),) and parent.nested == (irange(S25[1]),) and parent.excluded == ()
    assert child.pieces == (str(S25[1]),) and child.failed is None
    assert router.calls.count(("om", irange(S25[1]))) == 1 and router.count("om") == 2


def test_nested_child_with_a_different_holder_is_foreign(db, router):
    setup_contact(router, objs=[net4(A24, org=ORG, admin=[RL1]), net4(S25[1], org=ORG2, admin=[RL1])])
    router.om(irange(A24), [net4(S25[1], org=ORG2)])
    router.om(irange(S25[1]), [])
    c = run(db)
    parent = c.resources[0]
    assert parent.primary_key == irange(A24) and parent.nested == ()
    assert parent.excluded == (ripe.ExcludedChild(irange(S25[1]), "org", ORG2, (str(S25[1]),)),)
    assert parent.pieces == (str(S25[0]),)


def test_same_org_child_not_collected_is_counted_not_foreign(db, router):
    setup_contact(router, objs=[net4(A24, org=ORG, admin=[RL1])])
    router.om(irange(A24), [net4(S25[1], org=ORG)])
    r = only(run(db))
    assert r.nested_not_collected == 1 and r.excluded == () and r.nested == ()
    assert r.pieces == (str(S25[0]),)


def test_contact_held_parent_same_contact_child_in_set_is_nested(db, router):
    setup_contact(router, objs=[net4(A24, admin=[RL1]), net4(S25[1], admin=[RL1])])
    router.om(irange(A24), [net4(S25[1])])
    router.om(irange(S25[1]), [])
    parent = run(db).resources[0]
    assert parent.nested == (irange(S25[1]),) and parent.excluded == ()


def test_child_outside_parent_fails_closed(db, router):
    setup_contact(router, objs=[net4(S25[0], org=ORG, admin=[RL1])])
    router.om(irange(S25[0]), [net4(S25[1], org=ORG2)])
    r = only(run(db))
    assert r.failed == "bad_child" and r.pieces == ()
    assert router.count("om") == 1


def test_child_straddling_the_parent_edge_fails_closed(db, router):
    setup_contact(router, objs=[net4(S25[1], org=ORG, admin=[RL1])])
    straddle = f"{S25[0].broadcast_address - 1} - {S25[1].network_address + 1}"
    router.om(irange(S25[1]), [res("inetnum", straddle, org=ORG2)])
    assert only(run(db)).failed == "bad_child"


@pytest.mark.parametrize("child", [
    obj("inet6num", str(V6), [_attr("status", "ASSIGNED")]),
    obj("inetnum", irange(S25[1]), [_attr("status", "ASSIGNED PA")], source="apnic"),
    obj("inetnum", "garbage", [_attr("status", "ASSIGNED PA")]),
])
def test_unusable_child_fails_closed(db, router, child):
    setup_contact(router, objs=[net4(A24, org=ORG, admin=[RL1])])
    router.om(irange(A24), [child])
    r = only(run(db))
    assert r.failed == "bad_child" and r.pieces == ()


def test_failed_resource_keeps_excluded_collected_so_far(db, router):
    setup_contact(router, objs=[net4(A24, org=ORG, admin=[RL1])])
    router.om(irange(A24), [net4(S25[0], org=ORG2), net4(B24, org=ORG2)])
    r = only(run(db))
    assert r.failed == "bad_child" and r.pieces == () and len(r.excluded) == 1


def _v6_children(n, extra=None):
    all48 = list(V6.subnets(new_prefix=48))
    kids = all48[:2 * n:2]
    return kids + ([all48[extra]] if extra is not None else [])


def _pieces(kids):
    return len(ripe._remainder([V6], kids))


@pytest.mark.parametrize("n,failed", [(ripe.MAX_CHILDREN, None), (ripe.MAX_CHILDREN + 1, "too_many_children")])
def test_children_cap_fails_closed_one_over(db, router, n, failed):
    kids = list(V6.subnets(new_prefix=48))[:n]  # contiguous: few pieces, so only the children cap can trip
    setup_contact(router, objs=[res("inet6num", str(V6), org=ORG, admin=[RL1])])
    router.om(str(V6), [res("inet6num", str(k), org=ORG2) for k in kids])
    r = only(run(db))
    assert r.failed == failed
    if failed is None:
        assert r.pieces and len(r.excluded) == n  # the control reached the carve-out
    else:
        assert r.pieces == ()


def test_one_piece_over_the_cap_fails_closed(db, router):
    kids = _v6_children(53)
    assert _pieces(kids) == ripe.MAX_PIECES + 1  # the precondition: exactly one over
    setup_contact(router, objs=[res("inet6num", str(V6), org=ORG, admin=[RL1])])
    router.om(str(V6), [res("inet6num", str(k), org=ORG2) for k in kids])
    r = only(run(db))
    assert r.failed == "too_many_pieces" and r.pieces == () and len(r.excluded) == len(kids)


def test_piece_count_exactly_at_the_cap_is_allowed(db, router):
    kids = _v6_children(50, extra=104)
    assert _pieces(kids) == ripe.MAX_PIECES
    setup_contact(router, objs=[res("inet6num", str(V6), org=ORG, admin=[RL1])])
    router.om(str(V6), [res("inet6num", str(k), org=ORG2) for k in kids])
    r = only(run(db))
    assert r.failed is None and len(r.pieces) == ripe.MAX_PIECES


def test_error_response_on_one_more_fails_closed(db, router):
    setup_contact(router, objs=[net4(A24, org=ORG, admin=[RL1])])
    router.om(irange(A24), [net4(S25[1], org=ORG2)], errors=["Error"])
    r = only(run(db))
    assert r.failed == "error_response" and r.pieces == () and router.count("om") == 1


def test_http_error_on_one_more_is_counted(db, router):
    setup_contact(router, objs=[net4(A24, org=ORG, admin=[RL1])])
    router.om(irange(A24), [], status=500)
    c = run(db)
    r = only(c)
    assert r.failed == "fetch_failed" and r.pieces == () and c.fetch_failed == 1


def test_nothing_deeper_is_ever_fetched(db, router):
    setup_contact(router, objs=[net4(A24, org=ORG, admin=[RL1])])
    router.om(irange(A24), [net4(S25[1], org=ORG2)])
    router.om(irange(S25[1]), [net4(S25[1], org=ORG2)])
    run(db)
    assert router.calls.count(("om", irange(S25[1]))) == 0 and router.count("om") == 1


# ── budget, cache, determinism ───────────────────────────────────────────────

def test_budget_exhausted_on_one_more_fails_that_resource_and_stops(db, router):
    setup_contact(router, objs=[net4(A24, org=ORG, admin=[RL1]), net4(B24, org=ORG, admin=[RL1])])
    router.om(irange(A24), [])
    router.om(irange(B24), [])
    c = run(db, limit=2)  # full text + one inverse; the first one-more is over budget
    assert c.budget_exhausted and len(c.resources) == 2
    assert all(r.failed == "budget" and r.pieces == () for r in c.resources)
    assert len(router.calls) == 2 and router.count("om") == 0


def test_budget_exhausted_mid_contacts_stops_further_requests(db, router):
    router.ft([ft_doc(RL1, "role", [f"a@{DOM}"]), ft_doc(RL2, "role", [f"a@{DOM}"])])
    router.inv(RL1, [res("aut-num", "AS64500", admin=[RL1])])
    router.inv(RL2, [res("aut-num", "AS64501", admin=[RL2])])
    c = run(db, limit=2)
    assert c.budget_exhausted and [m.handle for m in c.matched] == [RL1, RL2]
    assert [r.asn for r in c.resources] == ["AS64500"]
    assert router.calls == [("ft", 0), ("inv", RL1, "contact")]


def test_budget_exhausted_on_fulltext_returns_empty(db, router):
    router.ft([ft_doc(RL1, "role", [f"a@{DOM}"])])
    c = run(db, limit=0)
    assert c.budget_exhausted and c.matched == () and c.resources == () and router.calls == []


def test_cached_rerun_makes_no_requests_and_is_identical(db, router):
    router.ft([ft_doc(RL1, "role", [f"a@{DOM}"])])
    router.inv(RL1, [organisation(ORG), net4(A24, admin=[RL1]), res("aut-num", "AS64500", admin=[RL1])])
    router.inv(ORG, [net4(B24, org=ORG)], kind="org")
    router.om(irange(A24), [net4(S25[1], org=ORG2)])
    router.om(irange(B24), [])
    first = run(db)
    n = len(router.calls)
    assert n == 5 and len(first.resources) == 3
    budget = rf.Budget()
    second = ripe.collect(db, DOM, budget)
    assert len(router.calls) == n and budget.used == 0 and budget.cache_hits == n
    assert second == first


def test_after_exhaustion_even_a_cached_lookup_is_not_used(db, router):
    # B24's one-more is in the cache; everything else is fetched fresh
    setup_contact(router, objs=[net4(B24, org=ORG, admin=[RL1])])
    router.om(irange(B24), [])
    run(db)
    db.query(RirLookupCache).filter(~RirLookupCache.path.like("%one-more%")).delete(synchronize_session=False)
    db.flush()
    router.calls.clear()
    router.inv(RL1, [net4(A24, org=ORG, admin=[RL1]), net4(B24, org=ORG, admin=[RL1])])
    router.om(irange(A24), [])
    c = run(db, limit=2)  # full text + inverse; A24's one-more is over budget
    assert router.calls == [("ft", 0), ("inv", RL1, "contact")]
    assert c.budget_exhausted
    assert [(r.primary_key, r.failed, r.pieces) for r in c.resources] == [
        (irange(A24), "budget", ()), (irange(B24), "budget", ())]
