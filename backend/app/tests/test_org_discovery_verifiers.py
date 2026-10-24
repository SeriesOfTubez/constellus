"""Org-discovery verifiers (planning#277 S1b part A): the vocabulary lists,
`fold_org`, `domain_facts.collect` over a fake resolver, the four pure rules,
`verify_pair`'s writes, family semantics through the strength SQL, and
migration 0084's column.

Synthetic data only (fabrikam.*, contoso.*, example.net, RFC 5737 / 3849 IPs).

Run with:  scripts/test.sh app/tests/test_org_discovery_verifiers.py
"""

import json
from datetime import datetime, timezone
from types import SimpleNamespace

import dns.exception
import dns.resolver
import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError, IntegrityError

from app.models.scope_candidate import ScopeCandidate, ScopeSignal
from app.services import whois_service
from app.services.org_discovery import candidates as cd
from app.services.org_discovery import domain_facts, lists, verifiers
from app.services.org_discovery import strength as strength_sql
from app.services.org_discovery.domain_facts import DomainFacts
from app.tests._org_world import World, hexid
from app.tests.test_org_discovery_schema import _insert_candidate, _insert_signal


@pytest.fixture
def w():
    world = World()
    try:
        yield world
    finally:
        world.close()


# ── fakes ───────────────────────────────────────────────────────────────────


class FakeResolver:
    """`answers[(name, rdtype)]` is a list of rdata-like items, or an exception
    class/instance to raise. A missing key is NXDOMAIN. Every request is logged."""

    def __init__(self, answers, wild=None):
        self.answers = answers
        self.wild = wild or {}  # suffix -> answer for ANY name ending "." + suffix (TXT)
        self.calls: list[tuple[str, str]] = []

    def resolve(self, name, rdtype):
        self.calls.append((name, rdtype))
        found = self.answers.get((name, rdtype), dns.resolver.NXDOMAIN)
        if (name, rdtype) not in self.answers:
            for suffix, ans in self.wild.items():
                if rdtype == "TXT" and name.endswith("." + suffix):
                    found = ans
        if isinstance(found, type) and issubclass(found, BaseException):
            raise found()
        if isinstance(found, BaseException):
            raise found
        return found


def txt(s: str):
    return SimpleNamespace(strings=[s.encode()])


def ns_rr(host: str):
    return SimpleNamespace(target=host + ".")


def mx_rr(host: str, pref: int = 10):
    return SimpleNamespace(exchange=host + ".", preference=pref)


@pytest.fixture
def no_whois(monkeypatch):
    monkeypatch.setattr(whois_service, "lookup_domain_cached", lambda db, d: {"registrant_org": None})


def facts(domain: str, **kw) -> DomainFacts:
    base = dict(ns=(), mx=(), spf_senders=(), spf_includes=(), registrant_org=None,
                registrant_org_folded=None, lookup_errors=())
    base.update(kw)
    return DomainFacts(domain=domain, **base)


# ── lists ───────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("host", [
    "ns.cloudflare.com", "bob.ns.cloudflare.com.", "NS-123.AWSDNS-45.COM", "ns-9.awsdns-1.co.uk",
    "ns-1.awsdns-02.net", "ns-77.awsdns-12.org", "ns1-01.azure-dns.com", "ns2-01.azure-dns.net",
    "ns1.domaincontrol.com", "dns1.registrar-servers.com", "dns1.p01.nsone.net", "a1-1.akam.net",
    "ns1.dynect.net", "ns1.digitalocean.com", "ns1.linode.com", "ns1.gandi.net", "ns1.worldnic.com",
    "ns1.name.com", "ns-cloud-a1.googledomains.com", "ns1.vercel-dns.com",
])
def test_provider_ns_is_recognised(host):
    assert lists.is_provider_ns(host)


@pytest.mark.parametrize("host", [
    "ns1.fabrikam-dns.com", "ns1.fabrikam.com", "notcloudflare.com", "ns-1.awsdns-02.example.net",
    "awsdns-45.com", "ns-abc.awsdns-45.com", "", "name.com.fabrikam.com",
])
def test_vanity_ns_is_not_provider(host):
    assert not lists.is_provider_ns(host)


@pytest.mark.parametrize("domain", [
    "_spf.google.com", "spf.protection.outlook.com", "sendgrid.net", "u123.wl.sendgrid.net", "mailgun.org",
    "amazonses.com", "servers.mcsv.net", "spf.mandrillapp.com", "_spf.salesforce.com", "mktomail.com",
    "mail.zendesk.com", "spf.mtasv.net", "sparkpostmail.com", "spf.hubspot.com", "pphosted.com",
    "SPF.MIMECAST.COM.", "zoho.com", "_spf.atlassian.net", "email.freshdesk.com", "intercom.io",
    "klaviyomail.com", "spf.constantcontact.com", "spf.brevo.com", "spf.sendinblue.com",
])
def test_bulk_spf_include_is_recognised(domain):
    assert lists.is_bulk_spf_include(domain)


@pytest.mark.parametrize("domain", ["spf.fabrikam.com", "notsendgrid.net", "mail.contoso.com", ""])
def test_non_bulk_spf_include(domain):
    assert not lists.is_bulk_spf_include(domain)


# ── fold_org ────────────────────────────────────────────────────────────────


def test_fold_org_keeps_legal_suffix_and_folds_case_and_punctuation():
    assert lists.fold_org("Example Holdings, Inc.") == "example holdings inc"
    assert lists.fold_org("  EXAMPLE   holdings (A) Inc ") == "example holdings a inc"
    assert lists.fold_org("Example Holdings, Inc.") != lists.fold_org("Example Holdings, LLC")
    assert lists.fold_org("Ｅｘａｍｐｌｅ Holdings Inc") == "example holdings inc"  # NFKC


@pytest.mark.parametrize("pattern", lists.REGISTRANT_PRIVACY_PATTERNS)
def test_every_privacy_pattern_folds_to_none(pattern):
    assert lists.fold_org(f"Example Holdings {pattern.upper()} Ltd") is None
    assert lists.fold_org(pattern) is None


def test_privacy_pattern_checked_on_the_folded_form_too():
    # "Data-Protected" only contains "data protected" once punctuation is folded
    assert lists.fold_org("Example Data-Protected Inc") is None
    assert lists.fold_org("Not_Disclosed Ltd") is None


@pytest.mark.parametrize("raw", [None, "", "   ", "n/a", "N/A", "na", "None", "NULL", "-", "Not Available", "Unknown"])
def test_placeholders_fold_to_none(raw):
    assert lists.fold_org(raw) is None


@pytest.mark.parametrize("raw", ["ab", "A.", " x ", "!!"])
def test_short_orgs_fold_to_none(raw):
    assert lists.fold_org(raw) is None


# ── domain_facts.collect ────────────────────────────────────────────────────


def test_collect_reads_ns_mx_and_whois(no_whois):
    r = FakeResolver({
        ("fabrikam.com", "NS"): [ns_rr("NS2.Fabrikam-DNS.com"), ns_rr("ns1.fabrikam-dns.com")],
        ("fabrikam.com", "MX"): [mx_rr("Mail.Fabrikam.com"), mx_rr(".", 0)],
    })
    f = domain_facts.collect(None, "Fabrikam.com", resolver=r)
    assert f.domain == "fabrikam.com"
    assert f.ns == ("ns1.fabrikam-dns.com", "ns2.fabrikam-dns.com")
    assert f.mx == ("mail.fabrikam.com",)
    assert f.spf_senders == () and f.registrant_org is None and f.registrant_org_folded is None
    assert f.lookup_errors == ()  # no SPF record (NXDOMAIN) is an answer, not an error


def test_collect_whois_org_raw_and_folded(monkeypatch):
    monkeypatch.setattr(whois_service, "lookup_domain_cached", lambda db, d: {"registrant_org": " Example Holdings, Inc. "})
    f = domain_facts.collect(None, "fabrikam.com", resolver=FakeResolver({}))
    assert (f.registrant_org, f.registrant_org_folded) == ("Example Holdings, Inc.", "example holdings inc")


def test_collect_dns_failure_is_recorded_and_empty(no_whois):
    r = FakeResolver({
        ("fabrikam.com", "NS"): dns.exception.Timeout,
        ("fabrikam.com", "MX"): dns.resolver.NoAnswer,
        ("fabrikam.com", "TXT"): dns.resolver.NoNameservers,
    })
    f = domain_facts.collect(None, "fabrikam.com", resolver=r)
    assert f.ns == () and f.mx == () and f.spf_senders == ()
    assert f.lookup_errors == ("ns", "spf")  # MX NoAnswer: not an error
    assert [c for c in r.calls if c[1] == "NS"]  # the lookup was attempted


def test_collect_whois_failure_is_recorded(monkeypatch):
    def boom(db, d):
        raise RuntimeError("whois down")

    class Db:
        rolled = False

        def rollback(self):
            self.rolled = True

    monkeypatch.setattr(whois_service, "lookup_domain_cached", boom)
    db = Db()
    f = domain_facts.collect(db, "fabrikam.com", resolver=FakeResolver({}))
    assert f.lookup_errors == ("whois",) and f.registrant_org is None and db.rolled


def test_a_bulk_include_is_not_walked_but_a_vendor_include_is(no_whois):
    r = FakeResolver({
        ("fabrikam.com", "TXT"): [txt("v=spf1 include:_spf.google.com include:spf.vendor.fabrikam.net -all")],
        ("_spf.google.com", "TXT"): [txt("v=spf1 ip4:198.51.100.0/24 -all")],
        ("spf.vendor.fabrikam.net", "TXT"): [txt("v=spf1 ip4:203.0.113.7 -all")],
    })
    f = domain_facts.collect(None, "fabrikam.com", resolver=r)
    assert ("spf.vendor.fabrikam.net", "TXT") in r.calls  # the walk was reached ...
    assert ("_spf.google.com", "TXT") not in r.calls  # ... and skipped the bulk subtree
    assert f.spf_includes == ("_spf.google.com", "spf.vendor.fabrikam.net")
    assert f.spf_senders == ("203.0.113.7/32", "spf.vendor.fabrikam.net")  # bulk never a sender, nor its IPs


def test_spf_ip_normalisation_and_junk(no_whois):
    r = FakeResolver({("fabrikam.com", "TXT"): [txt(
        "v=spf1 ip4:192.0.2.1/24 ip6:2001:db8::1/32 ip4:not-an-ip ip4:999.1.1.1 a mx ptr exists:x.example.net ~all"
    )]})
    f = domain_facts.collect(None, "fabrikam.com", resolver=r)
    assert f.spf_senders == ("192.0.2.0/24", "2001:db8::/32")
    r2 = FakeResolver({("contoso.com", "TXT"): [txt("v=spf1 ip4:192.0.2.0/24 -all")]})
    g = domain_facts.collect(None, "contoso.com", resolver=r2)
    assert verifiers.match_spf(f, g).matched_values == ("192.0.2.0/24",)


def test_spf_negative_qualifiers_are_not_senders_and_not_walked(no_whois):
    rec = ("v=spf1 -ip4:192.0.2.0/24 ~include:soft.fabrikam.net ?include:neutral.fabrikam.net "
           "-include:hard.fabrikam.net -all")
    r1 = FakeResolver({("fabrikam.com", "TXT"): [txt(rec)],
                       ("soft.fabrikam.net", "TXT"): [txt("v=spf1 ip4:203.0.113.7 -all")]})
    r2 = FakeResolver({("contoso.com", "TXT"): [txt(rec)],
                       ("soft.fabrikam.net", "TXT"): [txt("v=spf1 ip4:203.0.113.7 -all")]})
    f = domain_facts.collect(None, "fabrikam.com", resolver=r1)
    g = domain_facts.collect(None, "contoso.com", resolver=r2)
    assert ("fabrikam.com", "TXT") in r1.calls  # the record really was read
    assert f.spf_senders == () and g.spf_senders == ()
    assert verifiers.match_spf(f, g) is None
    for r in (r1, r2):
        assert not [c for c in r.calls if c[0] in ("soft.fabrikam.net", "neutral.fabrikam.net", "hard.fabrikam.net")]


def test_spf_plus_qualifier_counts_like_a_bare_mechanism(no_whois):
    r1 = FakeResolver({("fabrikam.com", "TXT"): [txt("v=spf1 +ip4:192.0.2.0/24 -all")]})
    r2 = FakeResolver({("contoso.com", "TXT"): [txt("v=spf1 ip4:192.0.2.0/24 -all")]})
    f = domain_facts.collect(None, "fabrikam.com", resolver=r1)
    g = domain_facts.collect(None, "contoso.com", resolver=r2)
    assert f.spf_senders == ("192.0.2.0/24",)
    assert verifiers.match_spf(f, g).matched_values == ("192.0.2.0/24",)


def _spf_senders(no_whois_unused, mech: str):
    r = FakeResolver({("fabrikam.com", "TXT"): [txt(f"v=spf1 {mech} -all")]})
    return domain_facts.collect(None, "fabrikam.com", resolver=r)


@pytest.mark.parametrize("mech,expected", [
    ("ip4:0.0.0.0/0", ()),
    ("ip4:10.0.0.0/15", ()),
    ("ip4:10.0.0.0/16", ("10.0.0.0/16",)),
    ("ip6:2001:db8::/32", ("2001:db8::/32",)),
    ("ip6:2001:db8::/31", ()),
])
def test_spf_overbroad_networks_are_dropped_at_the_boundary(no_whois, mech, expected):
    f = _spf_senders(None, mech)
    assert f.spf_senders == expected
    other = domain_facts.collect(None, "contoso.com", resolver=FakeResolver(
        {("contoso.com", "TXT"): [txt(f"v=spf1 {mech} -all")]}))
    m = verifiers.match_spf(f, other)
    assert (m is None) == (expected == ())
    if expected:
        assert m.matched_values == expected


def test_spf_lookup_cap(no_whois):
    includes = " ".join(f"include:i{n}.fabrikam.net" for n in range(14))
    answers = {("fabrikam.com", "TXT"): [txt(f"v=spf1 {includes} -all")]}
    for n in range(14):
        answers[(f"i{n}.fabrikam.net", "TXT")] = [txt("v=spf1 ip4:203.0.113.7 -all")]
    r = FakeResolver(answers)
    f = domain_facts.collect(None, "fabrikam.com", resolver=r)
    nested = [c for c in r.calls if c[0].startswith("i")]
    assert len(nested) == 10  # RFC 7208 cap: the 11th..14th include are recorded, not fetched
    assert len(f.spf_includes) == 14


def test_spf_cycle_is_walked_once(no_whois):
    r = FakeResolver({
        ("fabrikam.com", "TXT"): [txt("v=spf1 include:a.fabrikam.net -all")],
        ("a.fabrikam.net", "TXT"): [txt("v=spf1 include:b.fabrikam.net -all")],
        ("b.fabrikam.net", "TXT"): [txt("v=spf1 include:a.fabrikam.net include:fabrikam.com -all")],
    })
    f = domain_facts.collect(None, "fabrikam.com", resolver=r)
    assert r.calls.count(("a.fabrikam.net", "TXT")) == 1 and r.calls.count(("b.fabrikam.net", "TXT")) == 1
    assert {"a.fabrikam.net", "b.fabrikam.net"}.issubset(f.spf_senders)


def test_walk_state_flags_the_cap():
    includes = " ".join(f"include:i{n}.fabrikam.net" for n in range(12))
    state = {"lookups": 0, "exceeds_limit": False, "senders": set(), "includes": set()}
    domain_facts.walk_spf_senders(FakeResolver({}), "fabrikam.com", f"v=spf1 {includes}", state, set())
    assert state["exceeds_limit"]


# ── the four rules ──────────────────────────────────────────────────────────


def test_match_ns_positive_and_negative():
    c = facts("fabrikam.net", ns=("ns1.fabrikam.com", "ns2.fabrikam.com"))
    a = facts("fabrikam.com", ns=("ns1.fabrikam.com", "ns9.other.example.net"))
    m = verifiers.match_ns(c, a)
    assert m.signal_type == "shared_vanity_ns" and m.matched_values == ("ns1.fabrikam.com",)
    assert m.quote == "fabrikam.net and claimed fabrikam.com share nameserver ns1.fabrikam.com"
    assert verifiers.match_ns(c, facts("fabrikam.com", ns=("ns1.contoso-dns.com",))) is None
    assert verifiers.match_ns(c, facts("fabrikam.com")) is None


def test_match_ns_drops_providers_including_route53():
    shared = ("ns-123.awsdns-45.com", "ns-9.awsdns-1.co.uk", "bob.ns.cloudflare.com", "ns1-01.azure-dns.com")
    assert verifiers.match_ns(facts("fabrikam.net", ns=shared), facts("fabrikam.com", ns=shared)) is None
    mixed = shared + ("ns1.fabrikam.com",)
    m = verifiers.match_ns(facts("fabrikam.net", ns=mixed), facts("fabrikam.com", ns=mixed))
    assert m.matched_values == ("ns1.fabrikam.com",)


def test_match_ns_shared_host_under_no_claimed_domain_is_not_vanity():
    shared = ("ns1.smallhoster.example.net", "ns2.smallhoster.example.net")
    c, a = facts("fabrikam.net", ns=shared), facts("fabrikam.com", ns=shared)
    assert set(c.ns) & set(a.ns) == set(shared)  # really shared, so the None below is the rule's doing
    assert verifiers.match_ns(c, a) is None
    # a claimed domain that is not the host's owner does not rescue it
    assert verifiers.match_ns(c, a, frozenset({"contoso.com"})) is None
    # control: the same shape under a claimed domain matches
    assert verifiers.match_ns(c, a, frozenset({"smallhoster.example.net"})) is not None


def test_match_ns_host_under_a_third_claimed_domain_matches():
    c = facts("fabrikam.net", ns=("ns1.contoso.com",))
    a = facts("fabrikam.com", ns=("ns1.contoso.com",))
    assert verifiers.match_ns(c, a) is None  # contoso.com unknown without claimed_domains
    m = verifiers.match_ns(c, a, frozenset({"contoso.com"}))
    assert m.matched_values == ("ns1.contoso.com",)
    # suffix lookalike is not "under"
    c2 = facts("fabrikam.net", ns=("ns1.notcontoso.com",))
    a2 = facts("fabrikam.com", ns=("ns1.notcontoso.com",))
    assert verifiers.match_ns(c2, a2, frozenset({"contoso.com"})) is None


def test_match_ns_host_under_the_candidates_own_domain_matches():
    c = facts("fabrikam.net", ns=("ns1.fabrikam.net",))
    a = facts("fabrikam.com", ns=("ns1.fabrikam.net",))
    assert verifiers.match_ns(c, a).matched_values == ("ns1.fabrikam.net",)


def test_match_mx():
    a = facts("fabrikam.com", mx=("mx1.mailhost.example.net",))
    # a host under the claimed domain
    m = verifiers.match_mx(facts("fabrikam.net", mx=("mail.fabrikam.com",)), a)
    assert m.signal_type == "mx_into_claimed" and m.matched_values == ("mail.fabrikam.com",)
    # the claimed domain itself
    assert verifiers.match_mx(facts("fabrikam.net", mx=("fabrikam.com",)), a).matched_values == ("fabrikam.com",)
    # the very same non-provider host
    assert verifiers.match_mx(facts("fabrikam.net", mx=("mx1.mailhost.example.net",)), a)
    # a host merely ending in the claimed name is not "under" it
    assert verifiers.match_mx(facts("fabrikam.net", mx=("mail.notfabrikam.com",)), a) is None
    assert verifiers.match_mx(facts("fabrikam.net", mx=("mx.contoso.com",)), a) is None


def test_provider_managed_mx_never_matches_even_when_shared():
    both = ("aspmx.l.google.com", "mx1.pphosted.com", "mail.protection.outlook.com")
    assert verifiers.match_mx(facts("fabrikam.net", mx=both), facts("fabrikam.com", mx=both)) is None


def test_match_spf():
    a = facts("fabrikam.com", spf_senders=("192.0.2.0/24", "spf.vendor.fabrikam.net"))
    m = verifiers.match_spf(facts("fabrikam.net", spf_senders=("192.0.2.0/24", "198.51.100.0/24")), a)
    assert m.signal_type == "spf_sender_shared" and m.matched_values == ("192.0.2.0/24",)
    # an include under the claimed domain, shared with nobody else
    m = verifiers.match_spf(facts("fabrikam.net", spf_senders=("_spf.fabrikam.com",)), a)
    assert m.matched_values == ("_spf.fabrikam.com",)
    # union of both routes
    m = verifiers.match_spf(
        facts("fabrikam.net", spf_senders=("192.0.2.0/24", "_spf.fabrikam.com", "198.51.100.0/24")), a
    )
    assert m.matched_values == ("192.0.2.0/24", "_spf.fabrikam.com")
    assert verifiers.match_spf(facts("fabrikam.net", spf_senders=("198.51.100.0/24",)), a) is None
    assert verifiers.match_spf(facts("fabrikam.net", spf_senders=("_spf.notfabrikam.com",)), a) is None


def test_match_registrant_org():
    c = facts("fabrikam.net", registrant_org="Example Holdings A Inc.", registrant_org_folded="example holdings a inc")
    a = facts("fabrikam.com", registrant_org="EXAMPLE HOLDINGS A, INC", registrant_org_folded="example holdings a inc")
    m = verifiers.match_registrant_org(c, a)
    assert m.signal_type == "registrant_org_match" and m.matched_values == ("example holdings a inc",)
    assert m.evidence["candidate_registrant_org"] == "Example Holdings A Inc."
    assert m.evidence["claimed_registrant_org"] == "EXAMPLE HOLDINGS A, INC"
    other = facts("fabrikam.com", registrant_org="Example Holdings A LLC", registrant_org_folded="example holdings a llc")
    assert verifiers.match_registrant_org(c, other) is None  # suffix kept
    blank = facts("fabrikam.com")
    assert verifiers.match_registrant_org(blank, blank) is None  # two Nones never match


def test_quote_is_capped_and_evidence_is_deterministic_json():
    hosts = tuple(f"ns{n:03d}.fabrikam.com" for n in range(60))
    c, a = facts("fabrikam.net", ns=hosts), facts("fabrikam.com", ns=hosts)
    m = verifiers.match_ns(c, a)
    assert len(m.quote) <= 2000 and "+57 more" in m.quote and len(m.matched_values) == 60
    again = verifiers.match_ns(c, a)
    assert json.dumps(m.evidence, sort_keys=True) == json.dumps(again.evidence, sort_keys=True)


# ── verify_pair ─────────────────────────────────────────────────────────────


def _claim(w, candidate, entity):
    w.db.execute(ScopeCandidate.__table__.update().where(ScopeCandidate.id == candidate.id).values(
        status="claimed", affiliated_entity_id=entity.id, decided_at=datetime.now(timezone.utc), accepted_into="estate",
    ))
    w.db.commit()
    w.db.refresh(candidate)


def _pair(w):
    """(root, open candidate fabrikam.net-like, claimed anchor fabrikam.com-like)."""
    root = w.ours()
    anchor = w.candidate(root, value=f"anc-{hexid()}.fabrikam.com")
    _claim(w, anchor, root)
    cand = w.candidate(root, value=f"cand-{hexid()}.fabrikam.net")
    return root, cand, anchor


def _matching(cand, anchor, **extra):
    shared = dict(ns=(f"ns1.{anchor.value}",), mx=("mx.fabrikam-mail.example.net",))
    return facts(cand.value, **shared, **extra), facts(anchor.value, **shared)


def _signals(w, cand, signal_type=None):
    q = select(ScopeSignal).where(ScopeSignal.candidate_id == cand.id)
    if signal_type:
        q = q.where(ScopeSignal.signal_type == signal_type)
    return w.db.execute(q.execution_options(populate_existing=True)).scalars().all()


def test_verify_pair_writes_signals_with_matched_values_evidence_and_quote(w):
    root, cand, anchor = _pair(w)
    cf, af = _matching(cand, anchor, registrant_org="Example Holdings A Inc", registrant_org_folded="example holdings a inc")
    af = DomainFacts(**{**af.__dict__, "registrant_org": "Example Holdings A Inc.",
                        "registrant_org_folded": "example holdings a inc"})
    out = verifiers.verify_pair(w.db, candidate=cand, anchor=anchor, candidate_facts=cf, anchor_facts=af)
    w.db.commit()
    assert [o.signal.signal_type for o in out] == ["shared_vanity_ns", "mx_into_claimed", "registrant_org_match"]
    assert all(o.created_signal and o.outcome == "recorded" for o in out)
    by_type = {s.signal_type: s for s in _signals(w, cand)}
    ns = by_type["shared_vanity_ns"]
    assert ns.matched_values == [f"ns1.{anchor.value}"]
    assert by_type["registrant_org_match"].matched_values == ["example holdings a inc"]
    assert ns.anchor_kind == "claimed_candidate" and ns.anchor_candidate_id == anchor.id
    assert ns.via_entity_id == root.id
    assert cand.value in ns.quote and anchor.value in ns.quote
    body, ctype = w.db.execute(text(
        "select b.content, b.content_type from evidence_fetches f join evidence_blobs b on b.sha256 = f.sha256 "
        "where f.id = :i"), {"i": ns.evidence_id}).one()
    doc = json.loads(bytes(body))
    assert ctype == "application/json"
    assert doc["rule"] == "shared_vanity_ns" and doc["candidate"] == cand.value and doc["claimed"] == anchor.value
    assert doc["candidate_ns"] == [f"ns1.{anchor.value}"]


def test_a_second_identical_run_dedups(w):
    root, cand, anchor = _pair(w)
    cf, af = _matching(cand, anchor)
    kw = dict(candidate=cand, anchor=anchor, candidate_facts=cf, anchor_facts=af)
    first = verifiers.verify_pair(w.db, **kw)
    w.db.commit()
    second = verifiers.verify_pair(w.db, **kw)
    w.db.commit()
    assert [o.created_signal for o in first] == [True, True]
    assert [o.created_signal for o in second] == [False, False]
    assert len(_signals(w, cand, "shared_vanity_ns")) == 1
    assert {o.signal.id for o in first} == {o.signal.id for o in second}


def test_verify_pair_writes_nothing_when_the_pair_is_ineligible(w):
    root, cand, anchor = _pair(w)
    cf, af = _matching(cand, anchor)
    kw = dict(candidate=cand, anchor=anchor, candidate_facts=cf, anchor_facts=af)

    def count():
        return len(_signals(w, cand))

    before = count()
    # a rejected candidate
    w.db.execute(ScopeCandidate.__table__.update().where(ScopeCandidate.id == cand.id).values(
        status="rejected", decided_at=datetime.now(timezone.utc), rejection_reason="not ours", rejected_strong_types=[]))
    w.db.commit()
    w.db.refresh(cand)
    assert verifiers.verify_pair(w.db, **kw) == []
    # a claimed candidate
    claimed = w.candidate(root, value=f"claimed-{hexid()}.fabrikam.net")
    _claim(w, claimed, root)
    assert verifiers.verify_pair(
        w.db, candidate=claimed, anchor=anchor, candidate_facts=facts(claimed.value, ns=cf.ns), anchor_facts=af
    ) == []
    assert count() == before and _signals(w, claimed) == [s for s in _signals(w, claimed) if s.signal_type == "person_evidence"]

    # an OPEN anchor, the same candidate as its own anchor
    root2, cand2, _claimed_anchor = _pair(w)
    anchor2 = w.candidate(root2, value=f"open-{hexid()}.fabrikam.com")
    cf2, af2 = _matching(cand2, anchor2)
    assert verifiers.verify_pair(w.db, candidate=cand2, anchor=anchor2, candidate_facts=cf2, anchor_facts=af2) == []
    assert verifiers.verify_pair(w.db, candidate=cand2, anchor=cand2, candidate_facts=cf2, anchor_facts=cf2) == []
    assert _signals(w, cand2) == [s for s in _signals(w, cand2) if s.signal_type == "person_evidence"]

    # the same input, eligible: control that the rules DO fire for this data
    root3, cand3, anchor3 = _pair(w)
    cf3, af3 = _matching(cand3, anchor3)
    assert len(verifiers.verify_pair(w.db, candidate=cand3, anchor=anchor3, candidate_facts=cf3, anchor_facts=af3)) == 2
    # facts about the wrong domains
    assert verifiers.verify_pair(w.db, candidate=cand3, anchor=anchor3, candidate_facts=af3, anchor_facts=cf3) == []
    w.db.commit()


def test_a_cross_root_anchor_writes_nothing(w):
    root, cand, _anchor = _pair(w)
    root2 = w.ours()
    foreign = w.candidate(root2, value=f"foreign-{hexid()}.fabrikam.com")
    _claim(w, foreign, root2)
    cf, af = _matching(cand, foreign)
    assert verifiers.match_ns(cf, af) is not None  # the rules would fire
    assert verifiers.verify_pair(w.db, candidate=cand, anchor=foreign, candidate_facts=cf, anchor_facts=af) == []
    assert [s.signal_type for s in _signals(w, cand)] == ["person_evidence"]


def test_verify_pair_reads_claimed_domains_from_the_db_in_its_own_root_only(w):
    root, cand, anchor = _pair(w)
    second = w.candidate(root, value=f"second-{hexid()}.contoso.com")
    _claim(w, second, root)
    # a claimed domain in ANOTHER root: present, but must not count
    root2 = w.ours()
    foreign = w.candidate(root2, value=f"foreign-{hexid()}.contoso.net")
    _claim(w, foreign, root2)
    assert foreign.status == "claimed" and foreign.root_entity_id != root.id

    def run(host):
        cf = facts(cand.value, ns=(host,))
        af = facts(anchor.value, ns=(host,))
        return verifiers.verify_pair(w.db, candidate=cand, anchor=anchor, candidate_facts=cf, anchor_facts=af)

    out = run(f"ns1.{second.value}")  # under a second claimed domain of this root
    assert [o.signal.signal_type for o in out] == ["shared_vanity_ns"]
    assert out[0].signal.matched_values == [f"ns1.{second.value}"]
    assert run(f"ns1.{foreign.value}") == []  # under another root's claimed domain
    w.db.commit()


# ── family semantics, end to end through the strength SQL ───────────────────


def _strength(w, cand):
    s = strength_sql.strength_subquery(candidate_ids=[cand.id])
    row = w.db.execute(select(s.strength.label("strength"), s.proposable.label("proposable"))).one()
    return row.strength, bool(row.proposable)


def _drop_seed_signal(w, cand):
    """The helper candidate starts with one Strong person signal; remove it so only verifier signals count."""
    w.db.execute(text("delete from scope_signals where candidate_id = :c and signal_type = 'person_evidence'"), {"c": cand.id})
    w.db.commit()


def test_mail_counts_once_so_mx_plus_spf_is_a_lead_not_proposable(w):
    root, cand, anchor = _pair(w)
    _drop_seed_signal(w, cand)
    cf = facts(cand.value, mx=(f"mail.{anchor.value}",), spf_senders=("192.0.2.0/24",))
    af = facts(anchor.value, spf_senders=("192.0.2.0/24",))
    out = verifiers.verify_pair(w.db, candidate=cand, anchor=anchor, candidate_facts=cf, anchor_facts=af)
    w.db.commit()
    assert sorted(o.signal.signal_type for o in out) == ["mx_into_claimed", "spf_sender_shared"]
    assert _strength(w, cand) == ("lead", False)


def test_mx_plus_vanity_ns_is_proposable(w):
    root, cand, anchor = _pair(w)
    _drop_seed_signal(w, cand)
    cf = facts(cand.value, mx=(f"mail.{anchor.value}",), ns=(f"ns1.{anchor.value}",))
    af = facts(anchor.value, ns=(f"ns1.{anchor.value}",))
    out = verifiers.verify_pair(w.db, candidate=cand, anchor=anchor, candidate_facts=cf, anchor_facts=af)
    w.db.commit()
    assert sorted(o.signal.signal_type for o in out) == ["mx_into_claimed", "shared_vanity_ns"]
    assert _strength(w, cand) == ("supporting", True)


# ── migration 0084 and record_signal's matched_values ───────────────────────


def test_matched_values_is_immutable_and_never_empty(w):
    root = w.ours()
    cid = _insert_candidate(w.db, root.id, value=f"m84-{hexid()}.example.com")
    sid = _insert_signal(w.db, cid, root.id, matched_values=["a"])
    with pytest.raises(DBAPIError) as exc:
        w.db.execute(text("update scope_signals set matched_values = ARRAY['b'] where id = :i"), {"i": sid})
        w.db.commit()
    w.db.rollback()
    assert "only last_seen_at may change" in str(exc.value.orig)
    w.db.execute(text("update scope_signals set last_seen_at = now() where id = :i"), {"i": sid})  # control
    w.db.commit()
    with pytest.raises(IntegrityError) as exc2:
        _insert_signal(w.db, cid, root.id, signal_type="person_evidence", anchor_kind="person", matched_values=[],
                       evidence_id=w.evidence_row().id, quote="x")
    w.db.rollback()
    assert "ck_scope_signals_matched_values_nonempty" in str(exc2.value.orig)


def test_record_signal_validates_stores_sorted_and_deduplicated(w):
    root = w.ours()
    d = f"mv84-{hexid()}.example.com"

    def rec(values):
        ev = w.evidence_row()
        return cd.record_signal(
            w.db, root_entity_id=root.id, value=d, signal_type="person_evidence", anchor_kind="person",
            via_entity_id=root.id, evidence_id=ev.id, quote=f"see {d}", matched_values=values,
        )

    with pytest.raises(cd.CandidateInvalid, match="non-blank"):
        rec(["ok", "  "])
    with pytest.raises(cd.CandidateInvalid, match="must not be empty"):
        rec([])
    assert w.db.execute(text("select count(*) from scope_candidates where root_entity_id = :r"), {"r": root.id}).scalar_one() == 0
    out = rec(["b.example.net", "a.example.net", "b.example.net"])
    w.db.commit()
    assert out.signal.matched_values == ["a.example.net", "b.example.net"]


# ── DMARC: vendor table, parsing, collect ───────────────────────────────────

_VENDORS = list(lists.DMARC_VENDOR_REPORT_HOSTS)
_PER_CUSTOMER = [h for h, v in lists.DMARC_VENDOR_REPORT_HOSTS.items() if not v]
_ALL_SHARED = [h for h, v in lists.DMARC_VENDOR_REPORT_HOSTS.items() if "*" in v]


def test_vendor_table_has_both_kinds():
    assert _PER_CUSTOMER and _ALL_SHARED  # the parametrisations below are not empty


@pytest.mark.parametrize("host", _PER_CUSTOMER)
def test_dmarc_vendor_per_customer(host):
    assert lists.dmarc_vendor_address_kind(f"abc123@{host}") == "per_customer"
    assert lists.dmarc_vendor_address_kind(f"abc123@sub.{host.upper()}.") == "per_customer"


@pytest.mark.parametrize("host", _ALL_SHARED)
def test_dmarc_vendor_shared_via_star(host):
    assert lists.dmarc_vendor_address_kind(f"anything@{host}") == "shared"


def test_dmarc_vendor_shared_via_listed_local_part(monkeypatch):
    monkeypatch.setitem(lists.DMARC_VENDOR_REPORT_HOSTS, "vendor.example", frozenset({"reports"}))
    assert lists.dmarc_vendor_address_kind("reports@vendor.example") == "shared"
    assert lists.dmarc_vendor_address_kind("cust42@vendor.example") == "per_customer"


@pytest.mark.parametrize("address", [
    "a@fabrikam.com", "a@mail.contoso.example", "a@" + "x" + _VENDORS[0], "a@" + _VENDORS[0] + ".fabrikam.com",
])
def test_dmarc_non_vendor_and_label_boundary(address):
    assert lists.dmarc_vendor_address_kind(address) is None


@pytest.mark.parametrize("address", ["", "nohost", "a@b@" + _VENDORS[0], "@" + _VENDORS[0], "a@"])
def test_dmarc_vendor_malformed(address):
    assert lists.dmarc_vendor_address_kind(address) is None


def test_parse_dmarc():
    assert domain_facts.parse_dmarc("v=DMARC1; p=none; rua=mailto:a@fabrikam.com") == {
        "v": "DMARC1", "p": "none", "rua": "mailto:a@fabrikam.com"}
    assert domain_facts.parse_dmarc("p=none; v=DMARC1") is None  # v must be first
    assert domain_facts.parse_dmarc("v=DMARC2; p=none") is None
    assert domain_facts.parse_dmarc("") is None
    assert domain_facts.parse_dmarc("  V = dmarc1 ;; junk; =x; P=reject ;") is not None  # case, junk tolerated
    t = domain_facts.parse_dmarc("V=dmarc1;;junk;RUA=mailto:a@fabrikam.com")
    assert t["rua"] == "mailto:a@fabrikam.com" and t["junk"] == ""


def test_parse_report_uris():
    p = domain_facts.parse_report_uris
    assert p("mailto:A@Fabrikam.com, mailto:b@contoso.com!10m") == ("a@fabrikam.com", "b@contoso.com")
    assert p("mailto:a@fabrikam.com?subject=x") == ("a@fabrikam.com",)
    assert p("MAILTO:a%40fabrikam.com") == ("a@fabrikam.com",)
    assert p("https://fabrikam.com/r, ftp://x, a@fabrikam.com") == ()
    assert p("foobar:a@fabrikam.com") == ()  # a 7-char non-mailto scheme still is not mailto
    assert p("mailto:a@b@fabrikam.com,mailto:a@bad_host.com,mailto:a@localhost,mailto:a@-x.com,"
             "mailto:@fabrikam.com,mailto:a b@fabrikam.com,mailto:a@fabrikam..com") == ()
    assert p("mailto:a@fabrikam.com,mailto:A@FABRIKAM.com") == ("a@fabrikam.com",)
    assert p("mailto:" + "a" * 65 + "@fabrikam.com") == ()
    many = ",".join(f"mailto:u{n}@fabrikam.com" for n in range(15))
    assert len(p(many)) == 10 and p(many)[0] == "u0@fabrikam.com"


def _dm(domain, rec, extra=None, wild=None):
    answers = {(f"_dmarc.{domain}", "TXT"): [txt(rec)]}
    answers.update(extra or {})
    return FakeResolver(answers, wild)


def test_collect_reads_rua_and_ruf(no_whois):
    r = _dm("fabrikam.com", "v=DMARC1; p=none; rua=mailto:r@fabrikam.com; ruf=mailto:f@fabrikam.com")
    f = domain_facts.collect(None, "fabrikam.com", resolver=r)
    assert f.dmarc_record_name == "_dmarc.fabrikam.com"
    assert f.dmarc_rua == ("r@fabrikam.com",) and f.dmarc_ruf == ("f@fabrikam.com",)
    assert f.dmarc_report_auth == () and f.lookup_errors == ()
    assert not [c for c in r.calls if "_report._dmarc" in c[0]]  # in-org: no authorisation lookup


def test_collect_two_dmarc_records_is_no_policy_and_no_error(no_whois):
    r = FakeResolver({("_dmarc.fabrikam.com", "TXT"): [
        txt("v=DMARC1; rua=mailto:a@fabrikam.com"), txt("v=DMARC1; rua=mailto:b@fabrikam.com")]})
    f = domain_facts.collect(None, "fabrikam.com", resolver=r)
    assert ("_dmarc.fabrikam.com", "TXT") in r.calls  # reached
    assert f.dmarc_record_name is None and f.dmarc_rua == () and "dmarc" not in f.lookup_errors


def test_collect_non_dmarc_txt_is_ignored(no_whois):
    r = FakeResolver({("_dmarc.fabrikam.com", "TXT"): [txt("something else"), txt("v=DMARC1; rua=mailto:a@fabrikam.com")]})
    f = domain_facts.collect(None, "fabrikam.com", resolver=r)
    assert f.dmarc_rua == ("a@fabrikam.com",)


def test_collect_subdomain_falls_back_to_apex(no_whois):
    r = _dm("fabrikam.com", "v=DMARC1; rua=mailto:a@fabrikam.com")
    f = domain_facts.collect(None, "mail.fabrikam.com", resolver=r)
    assert [c[0] for c in r.calls if c[0].startswith("_dmarc.")] == ["_dmarc.mail.fabrikam.com", "_dmarc.fabrikam.com"]
    assert f.dmarc_record_name == "_dmarc.fabrikam.com" and f.dmarc_rua == ("a@fabrikam.com",)
    own = _dm("mail.fabrikam.com", "v=DMARC1; rua=mailto:s@fabrikam.com", {
        ("_dmarc.fabrikam.com", "TXT"): [txt("v=DMARC1; rua=mailto:a@fabrikam.com")]})
    g = domain_facts.collect(None, "mail.fabrikam.com", resolver=own)
    assert g.dmarc_record_name == "_dmarc.mail.fabrikam.com" and g.dmarc_rua == ("s@fabrikam.com",)


def test_collect_failed_subdomain_lookup_does_not_fall_back(no_whois):
    r = _dm("fabrikam.com", "v=DMARC1; rua=mailto:a@fabrikam.com",
            {("_dmarc.mail.fabrikam.com", "TXT"): dns.exception.Timeout})
    f = domain_facts.collect(None, "mail.fabrikam.com", resolver=r)
    assert ("_dmarc.mail.fabrikam.com", "TXT") in r.calls  # attempted
    assert ("_dmarc.fabrikam.com", "TXT") not in r.calls
    assert f.dmarc_record_name is None and f.dmarc_rua == () and "dmarc" in f.lookup_errors


def test_collect_failed_apex_fallback_records_error(no_whois):
    r = FakeResolver({("_dmarc.fabrikam.com", "TXT"): dns.resolver.NoNameservers})
    f = domain_facts.collect(None, "mail.fabrikam.com", resolver=r)
    assert ("_dmarc.fabrikam.com", "TXT") in r.calls and f.lookup_errors == ("dmarc",)


def test_collect_no_dmarc_record_issues_no_report_auth_query(no_whois):
    r = FakeResolver({})
    f = domain_facts.collect(None, "fabrikam.com", resolver=r)
    assert ("_dmarc.fabrikam.com", "TXT") in r.calls  # the lookup happened ...
    assert not [c for c in r.calls if "_report._dmarc" in c[0]]  # ... and nothing followed
    assert f.dmarc_record_name is None and f.dmarc_report_auth == () and f.lookup_errors == ()


_EXT = "reports.contoso.example"


def _ext(rec_host=_EXT, apex="fabrikam.com", domain=None, **kw):
    domain = domain or apex
    rec = f"v=DMARC1; rua=mailto:x@{rec_host}"
    return _dm(domain, rec, kw.get("extra"), kw.get("wild"))


def test_report_auth_authorised(no_whois):
    r = _ext(extra={(f"fabrikam.com._report._dmarc.{_EXT}", "TXT"): [txt("v=DMARC1")]})
    f = domain_facts.collect(None, "fabrikam.com", resolver=r)
    assert f.dmarc_report_auth == ((_EXT, "authorised"),) and f.lookup_errors == ()
    names = [c[0] for c in r.calls if "_report._dmarc" in c[0]]
    assert len(names) == 2 and names[0] == f"fabrikam.com._report._dmarc.{_EXT}"  # specific then probe


def test_report_auth_absent_nxdomain_and_no_probe(no_whois):
    r = _ext()
    f = domain_facts.collect(None, "fabrikam.com", resolver=r)
    assert f.dmarc_report_auth == ((_EXT, "absent"),)
    assert len([c for c in r.calls if "_report._dmarc" in c[0]]) == 1  # no probe when nothing to probe against


def test_report_auth_non_dmarc_txt_is_absent(no_whois):
    r = _ext(extra={(f"fabrikam.com._report._dmarc.{_EXT}", "TXT"): [txt("hello")]})
    assert domain_facts.collect(None, "fabrikam.com", resolver=r).dmarc_report_auth == ((_EXT, "absent"),)


def test_report_auth_wildcard(no_whois):
    r = _ext(wild={f"_report._dmarc.{_EXT}": [txt("v=DMARC1")]})
    f = domain_facts.collect(None, "fabrikam.com", resolver=r)
    assert f.dmarc_report_auth == ((_EXT, "wildcard"),)


def test_report_auth_specific_error(no_whois):
    r = _ext(extra={(f"fabrikam.com._report._dmarc.{_EXT}", "TXT"): dns.exception.Timeout})
    f = domain_facts.collect(None, "fabrikam.com", resolver=r)
    assert f.dmarc_report_auth == ((_EXT, "error"),)
    assert f.lookup_errors == ("dmarc_report_auth",)


def test_report_auth_probe_error(no_whois):
    r = _ext(extra={(f"fabrikam.com._report._dmarc.{_EXT}", "TXT"): [txt("v=DMARC1")]},
             wild={f"_report._dmarc.{_EXT}": dns.resolver.NoNameservers})
    f = domain_facts.collect(None, "fabrikam.com", resolver=r)
    assert f.dmarc_report_auth == ((_EXT, "error"),) and f.lookup_errors == ("dmarc_report_auth",)


def test_report_auth_skips_in_org_hosts(no_whois):
    r = _dm("fabrikam.com", "v=DMARC1; rua=mailto:a@fabrikam.com,mailto:b@dmarc.fabrikam.com")
    f = domain_facts.collect(None, "fabrikam.com", resolver=r)
    assert f.dmarc_rua == ("a@fabrikam.com", "b@dmarc.fabrikam.com")
    assert f.dmarc_report_auth == () and not [c for c in r.calls if "_report._dmarc" in c[0]]


def test_report_auth_cap_of_five(no_whois):
    hosts = [f"h{n}.contoso.example" for n in range(6)]
    rec = "v=DMARC1; rua=" + ",".join(f"mailto:x@{h}" for h in reversed(hosts))
    r = _dm("fabrikam.com", rec)
    f = domain_facts.collect(None, "fabrikam.com", resolver=r)
    assert dict(f.dmarc_report_auth) == {**{h: "absent" for h in hosts[:5]}, hosts[5]: "unchecked"}
    assert [h for h, _ in f.dmarc_report_auth] == hosts  # sorted by host
    assert len([c for c in r.calls if "_report._dmarc" in c[0]]) == 5
    assert not [c for c in r.calls if c[0].endswith(f"_report._dmarc.{hosts[5]}")]


def test_report_auth_name_uses_the_apex_for_a_subdomain(no_whois):
    r = _dm("mail.fabrikam.com", f"v=DMARC1; rua=mailto:x@{_EXT}")
    domain_facts.collect(None, "mail.fabrikam.com", resolver=r)
    assert (f"fabrikam.com._report._dmarc.{_EXT}", "TXT") in r.calls
    assert not [c for c in r.calls if c[0].startswith("mail.fabrikam.com._report")]


def test_collect_dmarc_is_deterministic_despite_the_random_probe(no_whois):
    def run():
        r = _ext(extra={(f"fabrikam.com._report._dmarc.{_EXT}", "TXT"): [txt("v=DMARC1")]})
        return domain_facts.collect(None, "fabrikam.com", resolver=r), r

    (a, ra), (b, rb) = run(), run()
    assert a == b and a.dmarc_report_auth == ((_EXT, "authorised"),)
    probe = lambda r: [c[0] for c in r.calls if "_report._dmarc" in c[0]][1]  # noqa: E731
    assert probe(ra) != probe(rb)  # the probe label really was random ...
    assert probe(ra).split(".")[0] not in repr(a)  # ... and is stored nowhere


# ── DMARC rules (slice B) ───────────────────────────────────────────────────

_V = _PER_CUSTOMER[0]
_SHARED_V = _ALL_SHARED[0]


def _rep(c_dom="cand.fabrikam.net", a_dom="fabrikam.com", status="authorised", **kw):
    addr = kw.pop("addr", f"dmarc@{a_dom}")
    host = addr.split("@")[1]
    auth = () if status is None else ((host, status),)
    c = facts(c_dom, dmarc_record_name=f"_dmarc.{c_dom}", dmarc_rua=(addr,), dmarc_report_auth=auth, **kw)
    return c, facts(a_dom)


def test_dmarc_report_authorised_matches_with_addresses_and_auth_evidence():
    c, a = _rep()
    m = verifiers.match_dmarc_report(c, a)
    assert m.signal_type == "dmarc_report_to_claimed"
    assert m.matched_values == ("dmarc@fabrikam.com",)
    assert m.evidence["report_auth"] == {"fabrikam.com": "authorised"}
    assert m.evidence["candidate_rua"] == ["dmarc@fabrikam.com"] and m.evidence["candidate_ruf"] == []
    assert m.evidence["candidate_dmarc_record_name"] == "_dmarc.cand.fabrikam.net"
    assert m.quote == (
        "cand.fabrikam.net sends DMARC reports to claimed fabrikam.com (dmarc@fabrikam.com), "
        "authorised in fabrikam.com's DNS"
    )


@pytest.mark.parametrize("status", ["wildcard", "absent", "error", "unchecked", None])
def test_dmarc_report_only_authorised_counts(status):
    c, a = _rep(status=status)
    assert verifiers.match_dmarc_report(c, a) is None
    c, a = _rep(status="authorised")  # same fixture, status restored: the path is reachable
    assert verifiers.match_dmarc_report(c, a) is not None


def test_dmarc_report_to_a_different_claimed_domain_is_not_this_pairs_signal():
    c, a = _rep(addr="dmarc@contoso.com")
    assert verifiers.match_dmarc_report(c, a) is None


def test_dmarc_report_ruf_counts_and_subdomain_of_anchor_matches():
    addr = "dmarc@reports.fabrikam.com"
    c = facts("cand.fabrikam.net", dmarc_ruf=(addr,), dmarc_report_auth=(("reports.fabrikam.com", "authorised"),))
    m = verifiers.match_dmarc_report(c, facts("fabrikam.com"))
    assert m.matched_values == (addr,) and m.evidence["candidate_ruf"] == [addr]


def test_dmarc_report_reverse_direction_is_not_a_match():
    a = facts("fabrikam.com", dmarc_rua=("dmarc@cand.fabrikam.net",),
              dmarc_report_auth=(("cand.fabrikam.net", "authorised"),))
    assert verifiers.match_dmarc_report(facts("cand.fabrikam.net"), a) is None


def _ex(c_rua=(), a_rua=(), c_ruf=(), c_dom="cand.fabrikam.net", a_dom="fabrikam.com"):
    return (facts(c_dom, dmarc_rua=tuple(c_rua), dmarc_ruf=tuple(c_ruf)),
            facts(a_dom, dmarc_rua=tuple(a_rua)))


def test_dmarc_exact_vendor_per_customer_address():
    addr = f"abc123@{_V}"
    c, a = _ex([addr], [addr])
    m = verifiers.match_dmarc_exact(c, a, frozenset({"fabrikam.com"}))
    assert m.signal_type == "dmarc_exact_vendor" and m.matched_values == (addr,)
    assert m.evidence["vendor_kind"] == {addr: "per_customer"}
    assert m.evidence["claimed_rua"] == [addr]


def test_dmarc_exact_vendor_suppresses_generic_and_carries_only_vendor_addresses():
    v, g = f"abc123@{_V}", "reports@mailbox.example"
    c, a = _ex([v, g], [v, g])
    m = verifiers.match_dmarc_exact(c, a, frozenset())
    assert m.signal_type == "dmarc_exact_vendor" and m.matched_values == (v,)


def test_dmarc_exact_shared_vendor_mailbox_and_non_vendor_are_generic():
    for addr in (f"abc123@{_SHARED_V}", "reports@mailbox.example"):
        c, a = _ex([addr], [addr])
        m = verifiers.match_dmarc_exact(c, a, frozenset())
        assert m.signal_type == "dmarc_exact_generic" and m.matched_values == (addr,)
        assert "vendor_kind" not in m.evidence


def test_dmarc_exact_ruf_of_candidate_counts():
    addr = f"abc123@{_V}"
    c, a = _ex(c_ruf=[addr], a_rua=[addr])
    assert verifiers.match_dmarc_exact(c, a, frozenset()).signal_type == "dmarc_exact_vendor"


@pytest.mark.parametrize("addr", ["x@fabrikam.com", "x@reports.fabrikam.com", "x@contoso.com", "x@cand.fabrikam.net",
                                  "x@other.fabrikam.net"])
def test_dmarc_exact_owned_or_reverse_addresses_are_not_exact_matches(addr):
    c, a = _ex([addr], [addr])
    assert verifiers.match_dmarc_exact(c, a, frozenset({"fabrikam.com", "contoso.com"})) is None
    # the same fixture with an unowned address does match: the exclusion above is what stopped it
    c, a = _ex(["x@mailbox.example"], ["x@mailbox.example"])
    assert verifiers.match_dmarc_exact(c, a, frozenset({"fabrikam.com", "contoso.com"})) is not None


def test_dmarc_exact_no_overlap_and_empty_records_are_none():
    c, a = _ex([f"a@{_V}"], [f"b@{_V}"])
    assert verifiers.match_dmarc_exact(c, a, frozenset()) is None
    c, a = _ex([], [])
    assert verifiers.match_dmarc_exact(c, a, frozenset()) is None


def test_dmarc_evidence_is_byte_identical_across_builds():
    addr = f"abc123@{_V}"
    c, a = _ex([addr], [addr])
    dump = lambda m: json.dumps(m.evidence, sort_keys=True, separators=(",", ":"))  # noqa: E731
    assert dump(verifiers.match_dmarc_exact(c, a, frozenset())) == dump(verifiers.match_dmarc_exact(c, a, frozenset()))
    c, a = _rep()
    assert dump(verifiers.match_dmarc_report(c, a)) == dump(verifiers.match_dmarc_report(c, a))


def test_verify_pair_writes_dmarc_report_signal_with_evidence_and_dedups(w):
    root, cand, anchor = _pair(w)
    addr = f"dmarc@{anchor.value}"
    cf = facts(cand.value, dmarc_record_name=f"_dmarc.{cand.value}", dmarc_rua=(addr,),
               dmarc_report_auth=((anchor.value, "authorised"),))
    af = facts(anchor.value)
    kw = dict(candidate=cand, anchor=anchor, candidate_facts=cf, anchor_facts=af)
    first = verifiers.verify_pair(w.db, **kw)
    w.db.commit()
    assert [o.signal.signal_type for o in first] == ["dmarc_report_to_claimed"] and first[0].created_signal
    s = _signals(w, cand, "dmarc_report_to_claimed")[0]
    assert s.matched_values == [addr]
    assert cand.value in s.quote and "authorised in" in s.quote
    body = w.db.execute(text(
        "select b.content from evidence_fetches f join evidence_blobs b on b.sha256 = f.sha256 where f.id = :i"),
        {"i": s.evidence_id}).scalar_one()
    doc = json.loads(bytes(body))
    assert doc["rule"] == "dmarc_report_to_claimed" and doc["report_auth"] == {anchor.value: "authorised"}
    again = verifiers.verify_pair(w.db, **kw)
    w.db.commit()
    assert [o.created_signal for o in again] == [False] and again[0].signal.id == first[0].signal.id
    assert len(_signals(w, cand, "dmarc_report_to_claimed")) == 1


def test_verify_pair_writes_dmarc_exact_vendor_and_dedups(w):
    root, cand, anchor = _pair(w)
    addr = f"abc123@{_V}"
    cf = facts(cand.value, dmarc_rua=(addr,))
    af = facts(anchor.value, dmarc_rua=(addr,))
    kw = dict(candidate=cand, anchor=anchor, candidate_facts=cf, anchor_facts=af)
    first = verifiers.verify_pair(w.db, **kw)
    w.db.commit()
    assert [o.signal.signal_type for o in first] == ["dmarc_exact_vendor"]
    assert _signals(w, cand, "dmarc_exact_vendor")[0].matched_values == [addr]
    again = verifiers.verify_pair(w.db, **kw)
    w.db.commit()
    assert [o.created_signal for o in again] == [False]
    assert len(_signals(w, cand, "dmarc_exact_vendor")) == 1


def test_verify_pair_passes_claimed_domains_to_the_dmarc_exact_rule(w):
    root, cand, anchor = _pair(w)
    third = w.candidate(root, value=f"third-{hexid()}.contoso.com")
    _claim(w, third, root)
    # both report to a mailbox under a THIRD claimed domain of the root: that is
    # dmarc_report_to_claimed territory (unauthorised here), never an exact match
    addr = f"dmarc@{third.value}"
    cf = facts(cand.value, dmarc_rua=(addr,))
    af = facts(anchor.value, dmarc_rua=(addr,))
    out = verifiers.verify_pair(w.db, candidate=cand, anchor=anchor, candidate_facts=cf, anchor_facts=af)
    w.db.commit()
    assert out == []
    # the path is reached: the same shape under an UNCLAIMED domain is generic
    loose = f"dmarc@loose-{hexid()}.contoso.org"
    out = verifiers.verify_pair(
        w.db, candidate=cand, anchor=anchor,
        candidate_facts=facts(cand.value, dmarc_rua=(loose,)), anchor_facts=facts(anchor.value, dmarc_rua=(loose,)),
    )
    w.db.commit()
    assert [o.signal.signal_type for o in out] == ["dmarc_exact_generic"]


def test_dmarc_supporting_plus_mx_is_a_lead_but_plus_vanity_ns_is_proposable(w):
    root, cand, anchor = _pair(w)
    _drop_seed_signal(w, cand)
    addr = f"abc123@{_V}"
    cf = facts(cand.value, mx=(f"mail.{anchor.value}",), dmarc_rua=(addr,))
    af = facts(anchor.value, dmarc_rua=(addr,))
    out = verifiers.verify_pair(w.db, candidate=cand, anchor=anchor, candidate_facts=cf, anchor_facts=af)
    w.db.commit()
    assert sorted(o.signal.signal_type for o in out) == ["dmarc_exact_vendor", "mx_into_claimed"]
    assert _strength(w, cand) == ("lead", False)  # both are the mail family
    _drop_seed_signal(w, cand)
    w.db.execute(text("delete from scope_signals where candidate_id = :c"), {"c": cand.id})
    w.db.commit()
    ns = (f"ns1.{anchor.value}",)
    cf = facts(cand.value, ns=ns, dmarc_rua=(addr,))
    af = facts(anchor.value, ns=ns, dmarc_rua=(addr,))
    out = verifiers.verify_pair(w.db, candidate=cand, anchor=anchor, candidate_facts=cf, anchor_facts=af)
    w.db.commit()
    assert sorted(o.signal.signal_type for o in out) == ["dmarc_exact_vendor", "shared_vanity_ns"]
    assert _strength(w, cand) == ("supporting", True)
