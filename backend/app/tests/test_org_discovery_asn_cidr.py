"""ASN and CIDR scope candidates (planning#278 S3a): schema, normalisation,
`record_signal`, the claim branches (CIDR, and ASN with its cascade), the
domain-only consumers' kind filters and the API.

Synthetic data only: RFC 5737 / RFC 3849 prefixes, RFC 5398 documentation
ASNs, `example.com` domains. Cloud ranges a test needs are inserted and
removed by the `cloud` fixture.

Run with:  scripts/test.sh app/tests/test_org_discovery_asn_cidr.py
"""

import ipaddress
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.core.database import SessionLocal
from app.models.cloud_range import CloudRange, CloudRangeMeta
from app.models.scope_candidate import ScopeCandidate, ScopeCandidateEvent
from app.models.target import Target, TargetType
from app.services import cloud_ranges
from app.services.org_discovery import candidates as cd
from app.services.org_discovery import runner
from app.services.org_discovery.domain_facts import DomainFacts
from app.tests._org_world import World, client, hexid
from app.tests.test_org_discovery_schema import _fails, _insert_candidate, _trigger_fails, _update

HANDLE = "EXAMPLE-HOLDINGS-A"


@pytest.fixture
def w():
    world = World()
    try:
        yield world
    finally:
        world.close()


class _Meta:
    """The single `cloud_ranges_meta` row: present for every test in this
    file (a claim of a CIDR or ASN needs the dataset loaded) unless the test
    removes it to prove the guard fails closed."""

    def __init__(self, db):
        self.db = db
        self.inserted = False

    def add(self) -> None:
        if self.db.get(CloudRangeMeta, True) is None:
            self.db.add(CloudRangeMeta(
                id=True, dataset_sha256="0" * 64, generated_at=datetime.now(timezone.utc), record_count=0,
                refreshed_at=datetime.now(timezone.utc), manifest={},
            ))
            self.db.commit()
            self.inserted = True

    def remove(self) -> None:
        self.db.rollback()
        self.db.execute(text("DELETE FROM cloud_ranges_meta"))
        self.db.commit()
        self.db.expire_all()


@pytest.fixture(autouse=True)
def meta(w):
    m = _Meta(w.db)
    had = w.db.get(CloudRangeMeta, True) is not None
    m.add()
    yield m
    w.db.rollback()
    if not had:
        m.remove()


@pytest.fixture
def cloud(w):
    """Insert a `cloud_ranges` row for one test; removed afterwards."""
    ids: list[uuid.UUID] = []

    def add(prefix: str) -> None:
        rid = uuid.uuid4()
        w.db.execute(CloudRange.__table__.insert().values(
            id=rid, prefix=prefix, ip_version=ipaddress.ip_network(prefix).version, provider="Example Cloud",
            service_class="compute", source="test",
        ))
        w.db.commit()
        ids.append(rid)

    yield add
    w.db.rollback()
    if ids:
        w.db.execute(CloudRange.__table__.delete().where(CloudRange.__table__.c.id.in_(ids)))
        w.db.commit()


def _net(n: int) -> str:
    # RFC 3849, in a corner no other module uses. IPv4 literals in the
    # `_docaddr` pool are forbidden here (test_docaddr_guard), and an address
    # per test case would exhaust it.
    return str(ipaddress.ip_network(f"2001:db8:278:{n:x}::/64"))  # n in 0..15; canonical form


def _record(w, root, value, kind, *, handle=HANDLE, rir="ripe", signal_type="person_evidence", quote=None, **kw):
    """`record_signal` for a person-anchored signal with fresh evidence; the
    default quote names the value the way an RIR record does."""
    if quote is None:
        quote = f"inetnum: {ipaddress.ip_network(value).network_address}" if kind == "cidr" else f"aut-num: {value}"
    ev = w.evidence_row()
    out = cd.record_signal(
        w.db, root_entity_id=root.id, value=value, kind=kind, rir=rir, rir_handle=handle,
        signal_type=signal_type, anchor_kind="person", via_entity_id=root.id, evidence_id=ev.id, quote=quote, **kw,
    )
    w.db.commit()
    return out


def _cidr(w, root, n, **kw) -> ScopeCandidate:
    return _record(w, root, _net(n), "cidr", **kw).candidate


def _asn_cand(w, root, value="AS64500", **kw) -> ScopeCandidate:
    return _record(w, root, value, "asn", **kw).candidate


def _raw(db, root_id, **over):
    return _insert_candidate(db, root_id, **over)


# ── schema ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("good", ["AS64500", "AS1", "AS4199999999"])
def test_asn_shape_accepts(w, good):
    _raw(w.db, w.ours().id, kind="asn", value=good, rir="ripe", rir_handle=HANDLE)


@pytest.mark.parametrize("bad", ["as64500", "64500", "AS0", "AS064500", "AS", "AS64500x", "AS12345678901"])
def test_asn_shape_rejects(w, bad):
    root = w.ours()
    _fails(w.db, "ck_scope_candidates_asn_shape",
           lambda: _raw(w.db, root.id, kind="asn", value=bad, rir="ripe", rir_handle=HANDLE))


@pytest.mark.parametrize("good", ["192.0.2.0/24", "198.51.100.0/24", "2001:db8::/32", "2001:db8:0:1::/64", "203.0.113.7/32"])
def test_cidr_shape_accepts(w, good):
    _raw(w.db, w.ours().id, kind="cidr", value=good, rir="arin", rir_handle=HANDLE)


@pytest.mark.parametrize("bad", ["2001:DB8::/32", "2001:db8:0:0::/32", "192.0.2.0/024", "192.0.2.0", "192.0.2.0/24 ", "x/24"])
def test_cidr_shape_rejects_non_canonical(w, bad):
    root = w.ours()
    _fails(w.db, "ck_scope_candidates_cidr_shape",
           lambda: _raw(w.db, root.id, kind="cidr", value=bad, rir="arin", rir_handle=HANDLE))


def test_cidr_host_bits_set_fails_the_insert(w):
    root = w.ours()
    with pytest.raises(DBAPIError):
        _raw(w.db, root.id, kind="cidr", value="192.0.2.1/24", rir="arin", rir_handle=HANDLE)
    w.db.rollback()


def test_rir_and_handle_are_set_iff_not_a_domain(w):
    root = w.ours()
    base = dict(kind="cidr", value="192.0.2.0/24")
    _fails(w.db, "ck_scope_candidates_rir_iff_number_resource",
           lambda: _raw(w.db, root.id, **base, rir=None, rir_handle=HANDLE))
    _fails(w.db, "ck_scope_candidates_rir_handle_iff_number_resource",
           lambda: _raw(w.db, root.id, **base, rir="arin", rir_handle=None))
    _fails(w.db, "ck_scope_candidates_rir_iff_number_resource", lambda: _raw(w.db, root.id, rir="arin"))
    _fails(w.db, "ck_scope_candidates_rir_handle_iff_number_resource", lambda: _raw(w.db, root.id, rir_handle="X"))
    _raw(w.db, root.id, **base, rir="arin", rir_handle=HANDLE)  # the good path


def test_rir_is_a_closed_list_and_the_handle_never_blank(w):
    root = w.ours()
    base = dict(kind="cidr", value="192.0.2.0/24")
    _fails(w.db, "ck_scope_candidates_rir", lambda: _raw(w.db, root.id, **base, rir="iana", rir_handle=HANDLE))
    _fails(w.db, "ck_scope_candidates_rir_handle_nonblank",
           lambda: _raw(w.db, root.id, **base, rir="ripe", rir_handle="  "))
    for i, rir in enumerate(("arin", "ripe", "apnic", "lacnic", "afrinic")):
        _raw(w.db, root.id, kind="cidr", value=f"2001:db8:{i + 1}::/48", rir=rir, rir_handle=HANDLE)


def test_rir_and_handle_are_immutable(w):
    root = w.ours()
    cid = _raw(w.db, root.id, kind="asn", value="AS64500", rir="ripe", rir_handle=HANDLE)
    for values in ({"rir": "arin"}, {"rir_handle": "OTHER-HANDLE"}):
        _trigger_fails(w.db, "immutable", lambda v=values: _update(w.db, ScopeCandidate, cid, **v))
    _update(w.db, ScopeCandidate, cid, rir="ripe", rir_handle=HANDLE)  # unchanged values are allowed
    w.db.commit()


def test_the_new_signal_types_are_registered_and_built_only_where_a_generator_exists():
    from app.services.org_discovery.tiers import SIGNALS

    expected = {
        "rir_contact_email_claimed": ("strong", "rir"), "rir_contact_email_unvalidated": ("supporting", "rir_unvalidated"),
        "rir_allocation_dedicated_ip": ("supporting", "rir_ip"), "peeringdb_website_claimed": ("supporting", "peeringdb"),
        "rir_reassigned_elsewhere": ("context", "rir"), "bgp_announced_not_allocated": ("context", "bgp"),
    }
    built = {
        "rir_contact_email_claimed", "rir_contact_email_unvalidated", "rir_reassigned_elsewhere",  # S3b1 ARIN
        "rir_allocation_dedicated_ip",  # S3c1
    }
    for name, (tier, family) in expected.items():
        spec = SIGNALS[name]
        assert (spec.tier, spec.family, spec.built) == (tier, family, name in built), name
        assert spec.label and spec.description
    assert "IS validated" not in SIGNALS["rir_contact_email_claimed"].description  # prose, not a marker
    assert "validated" in SIGNALS["rir_contact_email_claimed"].description


# ── normalisation ───────────────────────────────────────────────────────────


@pytest.mark.parametrize("raw,expected", [
    ("AS64500", "AS64500"), ("as64500", "AS64500"), ("64500", "AS64500"), ("  64500 ", "AS64500"),
    ("AS64496", "AS64496"), ("AS64511", "AS64511"), ("AS65536", "AS65536"), ("AS65551", "AS65551"),
    ("AS1", "AS1"), ("AS4199999999", "AS4199999999"),
])
def test_normalise_asn_accepts(raw, expected):
    assert cd.normalise_asn(raw) == expected


@pytest.mark.parametrize("raw", [
    "0", "AS0", "23456", "AS23456", "65535", "64512", "65000", "65534", "4200000000", "4294967294", "4294967295",
    "4294967296", "", "ASx", "AS-1", "1.5", "AS 1", "٣",
])
def test_normalise_asn_rejects(raw):
    with pytest.raises(cd.CandidateInvalid):
        cd.normalise_asn(raw)


@pytest.mark.parametrize("raw,expected", [
    ("192.0.2.0/24", "192.0.2.0/24"), ("198.51.100.0/24", "198.51.100.0/24"), ("203.0.113.0/24", "203.0.113.0/24"),
    ("2001:db8::/32", "2001:db8::/32"), ("2001:DB8:0:0::/48", "2001:db8::/48"), (" 2001:db8:1::/48 ", "2001:db8:1::/48"),
    ("2001:db8:0:1::/64", "2001:db8:0:1::/64"),
])
def test_normalise_cidr_accepts(raw, expected):
    assert cd.normalise_cidr(raw) == expected


@pytest.mark.parametrize("raw", [
    "192.0.2.1/24",                                  # host bits set
    "10.1.0.0/16", "172.16.0.0/12", "172.31.0.0/16", "192.168.1.0/24",  # RFC 1918
    "100.64.0.0/10", "100.100.0.0/16",               # CGNAT
    "127.0.0.0/8", "127.1.0.0/16",                   # loopback
    "169.254.0.0/16",                                # link-local
    "224.0.0.0/4", "239.1.0.0/16",                   # multicast
    "0.0.0.0/32", "0.0.0.0/8", "0.0.0.0/0",          # unspecified / everything
    "240.0.0.0/4", "255.255.255.255/32",             # reserved
    "0.0.0.0/1", "10.0.0.0/7", "192.168.0.0/15",     # overlap private space without being inside it
    "::1/128", "::/128", "::/0", "::/96", "::ffff:0:0/96", "::ffff:192.0.2.0/120", "::1.2.3.0/120",
    "fc00::/7", "fd00::/8", "fe80::/10", "fe80::/64", "ff00::/8", "ff02::/16",
    "8000::/1", "100::/64",                          # outside global unicast
    "not a cidr", "", "192.0.2.0/33", "2001:db8::/129",
])
def test_normalise_cidr_rejects(raw):
    with pytest.raises(cd.CandidateInvalid):
        cd.normalise_cidr(raw)


@pytest.mark.parametrize("value", ["192.0.2.0/24", "2001:db8::/32", "2001:db8:0:1::/64", "2001:db8::1/128", "203.0.113.4/30"])
def test_python_form_equals_the_postgres_form(w, value):
    canonical = cd.normalise_cidr(value)
    assert w.db.execute(text("select CAST(:v AS cidr)::text"), {"v": canonical}).scalar_one() == canonical


# ── record_signal ───────────────────────────────────────────────────────────


def test_record_signal_creates_an_asn_and_a_cidr_with_their_registry(w):
    root = w.ours()
    a = _record(w, root, "as64500", "asn", handle=f"  {HANDLE} ", rir="RIPE")
    c = _record(w, root, "2001:DB8:0:0::/48", "cidr", quote="inet6num: 2001:db8::/48", handle="Mixed-Case-Handle", rir="arin")
    assert a.created_candidate and c.created_candidate
    assert (a.candidate.kind, a.candidate.value, a.candidate.rir, a.candidate.rir_handle) == ("asn", "AS64500", "ripe", HANDLE)
    assert (c.candidate.kind, c.candidate.value, c.candidate.rir, c.candidate.rir_handle) == (
        "cidr", "2001:db8::/48", "arin", "Mixed-Case-Handle")  # the handle is kept as written
    again = _record(w, root, "AS64500", "asn")
    assert (again.created_candidate, again.candidate.id) == (False, a.candidate.id)  # new evidence: a new signal row
    assert w.db.query(ScopeCandidate).filter_by(root_entity_id=root.id, kind="asn").count() == 1


def test_a_different_registry_or_handle_for_an_existing_candidate_raises(w):
    root = w.ours()
    c = _cidr(w, root, 1)
    for kwargs in ({"handle": "OTHER-HANDLE"}, {"rir": "arin"}):
        with pytest.raises(cd.CandidateConflict, match="never moved"):
            _record(w, root, _net(1), "cidr", **kwargs)
        w.db.rollback()
    w.db.refresh(c)
    assert (c.rir, c.rir_handle) == ("ripe", HANDLE)


def test_registry_is_required_for_asn_and_cidr_and_refused_for_a_domain(w):
    root = w.ours()
    ev = w.evidence_row()
    common = dict(
        root_entity_id=root.id, signal_type="person_evidence", anchor_kind="person", via_entity_id=root.id,
        evidence_id=ev.id,
    )
    for kind, value, quote in (("asn", "AS64500", "AS64500"), ("cidr", "192.0.2.0/24", "192.0.2.0")):
        for extra in ({}, {"rir": "ripe"}, {"rir_handle": HANDLE}, {"rir": "iana", "rir_handle": HANDLE},
                      {"rir": "ripe", "rir_handle": "   "}):
            with pytest.raises(cd.CandidateInvalid):
                cd.record_signal(w.db, value=value, kind=kind, quote=quote, **common, **extra)
    with pytest.raises(cd.CandidateInvalid, match="only for an ASN or CIDR"):
        cd.record_signal(w.db, value="example.com", kind="domain", quote="example.com", rir="ripe", rir_handle=HANDLE, **common)
    w.db.rollback()
    assert w.db.query(ScopeCandidate).filter_by(root_entity_id=root.id).count() == 0


def test_the_quote_rule_per_kind(w):
    root = w.ours()
    # asn: the value, case-insensitively
    assert _record(w, root, "AS64501", "asn", quote="aut-num: as64501").candidate is not None
    with pytest.raises(cd.CandidateInvalid, match="ASN"):
        _record(w, root, "AS64502", "asn", quote="aut-num: AS64999")
    # cidr: the network address (RIPE 'start - end', ARIN startAddress, IPv6 as CIDR)
    assert _record(w, root, "192.0.2.0/24", "cidr", quote="inetnum: 192.0.2.0 - 192.0.2.255").candidate is not None
    assert _record(w, root, "198.51.100.0/24", "cidr", quote='"startAddress": "198.51.100.0"').candidate is not None
    assert _record(w, root, "2001:db8::/32", "cidr", quote="inet6num: 2001:db8::/32").candidate is not None
    with pytest.raises(cd.CandidateInvalid, match="network address"):
        _record(w, root, "203.0.113.0/24", "cidr", quote="inetnum: 198.51.100.0 - 198.51.100.255")
    w.db.rollback()
    # domain unchanged
    ev = w.evidence_row()
    with pytest.raises(cd.CandidateInvalid, match="domain as written"):
        cd.record_signal(
            w.db, root_entity_id=root.id, value="example.com", signal_type="person_evidence", anchor_kind="person",
            via_entity_id=root.id, evidence_id=ev.id, quote="nothing here",
        )
    w.db.rollback()


def test_a_context_signal_creates_no_asn_or_cidr_candidate_but_decorates_an_existing_one(w):
    root = w.ours()
    out = _record(w, root, "192.0.2.0/24", "cidr", signal_type="bgp_announced_not_allocated")
    assert out.outcome == "skipped_context_only" and out.candidate is None
    assert w.db.query(ScopeCandidate).filter_by(root_entity_id=root.id).count() == 0
    c = _cidr(w, root, 2)
    out = _record(w, root, _net(2), "cidr", signal_type="rir_reassigned_elsewhere")
    assert out.outcome == "recorded" and out.created_signal and out.candidate.id == c.id  # the positive path


def test_a_supporting_family_alone_is_a_lead_and_two_make_it_claimable(w):
    root = w.ours()
    lead = _record(w, root, _net(3), "cidr", signal_type="peeringdb_website_claimed").candidate
    with pytest.raises(cd.CandidateConflict, match="not enough evidence"):
        cd.claim(w.db, candidate_id=lead.id, user=w.user())
    _record(w, root, _net(3), "cidr", signal_type="rir_allocation_dedicated_ip")
    result = cd.claim(w.db, candidate_id=lead.id, user=w.user())
    w.track_target(result.target.value)
    assert result.candidate.status == "claimed"


# ── claim: cidr ─────────────────────────────────────────────────────────────


def test_claiming_a_cidr_into_the_estate_makes_a_cidr_target(w):
    root = w.ours()
    c = _cidr(w, root, 4)
    admin = w.user()
    result = cd.claim(w.db, candidate_id=c.id, user=admin)
    t = result.target
    w.track_target(t.value)
    assert (t.type, t.value, t.source_type, t.engagement_id, t.entity_id, t.verified) == (
        TargetType.CIDR.value, c.value, "candidate_cidr", None, root.id, True)
    assert (result.created, result.prefixes) == (True, [])
    assert (result.candidate.status, result.candidate.target_id, result.candidate.accepted_into) == ("claimed", t.id, "estate")
    assert w.db.query(ScopeCandidateEvent).filter_by(candidate_id=c.id, event="claimed").count() == 1


def test_claiming_a_cidr_for_a_deal_goes_into_its_engagement(w):
    root, eng = w.deal()
    c = _cidr(w, root, 5)
    result = cd.claim(w.db, candidate_id=c.id, user=w.user())
    w.track_target(result.target.value)
    assert (result.target.engagement_id, result.target.type, result.candidate.accepted_into) == (
        eng.id, "cidr", "engagement")


def test_a_cidr_target_elsewhere_is_a_conflict_that_names_a_prefix(w):
    root = w.ours()
    eng = w.engagement()
    c = _cidr(w, root, 6)
    w.db.add(Target(id=uuid.uuid4(), type="cidr", value=c.value, engagement_id=eng.id))
    w.db.commit()
    w.track_target(c.value)
    with pytest.raises(cd.CandidateConflict, match="that prefix is already a target"):
        cd.claim(w.db, candidate_id=c.id, user=w.user())
    w.db.refresh(c)
    assert c.status == "open"


def test_a_cidr_overlapping_cloud_space_is_refused_and_a_clear_one_is_not(w, cloud):
    root = w.ours()
    inside = _cidr(w, root, 7)
    cloud("2001:db8:278:7:8000::/65")  # a cloud range INSIDE the candidate
    supernet_hit = _record(w, root, "2001:db8:279:1::/64", "cidr").candidate
    cloud("2001:db8:279::/48")  # a cloud range CONTAINING the candidate
    for c in (inside, supernet_hit):
        with pytest.raises(cd.CandidateConflict, match="cloud"):
            cd.claim(w.db, candidate_id=c.id, user=w.user())
        w.db.refresh(c)
        assert c.status == "open" and c.target_id is None
        assert w.db.query(Target).filter(Target.value == c.value).count() == 0
    # control: the same fixture, a prefix that overlaps nothing, claims fine
    clear = _record(w, root, "203.0.113.0/24", "cidr").candidate
    result = cd.claim(w.db, candidate_id=clear.id, user=w.user())
    w.track_target(result.target.value)
    assert result.candidate.status == "claimed"


def test_overlaps_any(w, cloud):
    assert cloud_ranges.overlaps_any(w.db, "203.0.113.0/24") is False
    cloud("2001:db8:27b:a::/64")
    assert cloud_ranges.overlaps_any(w.db, "2001:db8:27b::/48") is True      # contains
    assert cloud_ranges.overlaps_any(w.db, "2001:db8:27b:a:1::/80") is True  # contained
    assert cloud_ranges.overlaps_any(w.db, "2001:db8:27b:a::/64") is True    # equal
    assert cloud_ranges.overlaps_any(w.db, "2001:db8:27b:b::/64") is False
    assert cloud_ranges.overlaps_any(w.db, "203.0.113.0/24") is False        # nothing else is loaded
    with pytest.raises(ValueError):
        cloud_ranges.overlaps_any(w.db, "2001:db8:27b:a::1/64")


# ── claim: asn ──────────────────────────────────────────────────────────────


def _targets(db, values):
    return db.query(Target).filter(Target.value.in_(values)).all()


def _claimed_events(db, ids):
    return db.query(ScopeCandidateEvent).filter(
        ScopeCandidateEvent.candidate_id.in_(ids), ScopeCandidateEvent.event == "claimed").count()


def test_claiming_an_asn_claims_its_handles_open_proposable_prefixes_only(w):
    root, other_root = w.ours(), w.ours()
    asn = _asn_cand(w, root)
    mine = [_cidr(w, root, 0), _cidr(w, root, 1)]
    rejected = _cidr(w, root, 2)
    cd.reject(w.db, candidate_id=rejected.id, user=w.user(), reason="reassigned away")
    elsewhere_handle = _cidr(w, root, 3, handle="OTHER-HANDLE")
    other_registry = _record(w, root, _net(4), "cidr", rir="arin").candidate
    lead = _record(w, root, _net(5), "cidr", signal_type="peeringdb_website_claimed").candidate  # below the bar
    foreign = _cidr(w, other_root, 6)
    already = _cidr(w, root, 7)
    pre = cd.claim(w.db, candidate_id=already.id, user=w.user())
    all_values = [_net(n) for n in range(8)]
    for v in all_values:
        w.track_target(v)
    before_events = _claimed_events(w.db, [already.id])

    result = cd.claim(w.db, candidate_id=asn.id, user=w.user())

    assert result.target is None and result.created is False
    assert {p.candidate.id for p in result.prefixes} == {c.id for c in mine}
    w.db.refresh(asn)
    assert (asn.status, asn.target_id, asn.accepted_into, asn.affiliated_entity_id) == ("claimed", None, "estate", root.id)
    assert _claimed_events(w.db, [asn.id]) == 1
    for c in mine:
        w.db.refresh(c)
        t = w.db.get(Target, c.target_id)
        assert (c.status, t.type, t.value, t.source_type, t.entity_id, t.engagement_id) == (
            "claimed", "cidr", c.value, "candidate_cidr", root.id, None)
        assert _claimed_events(w.db, [c.id]) == 1
    for c, status in ((rejected, "rejected"), (elsewhere_handle, "open"), (other_registry, "open"),
                      (lead, "open"), (foreign, "open")):
        w.db.refresh(c)
        assert (c.status, c.target_id) == (status, None), c.value
        assert _claimed_events(w.db, [c.id]) == 0
    assert _claimed_events(w.db, [already.id]) == before_events  # left alone
    assert {t.value for t in _targets(w.db, all_values)} == {_net(0), _net(1), _net(7)}
    assert pre.target.id == w.db.get(ScopeCandidate, already.id).target_id


def test_claiming_an_asn_into_a_deal_puts_the_prefix_targets_in_its_engagement(w):
    root, eng = w.deal()
    asn = _asn_cand(w, root)
    c = _cidr(w, root, 8)
    w.track_target(c.value)
    result = cd.claim(w.db, candidate_id=asn.id, user=w.user())
    assert [p.target.engagement_id for p in result.prefixes] == [eng.id]


def test_an_asn_with_no_prefixes_still_claims(w):
    root = w.ours()
    asn = _asn_cand(w, root)
    result = cd.claim(w.db, candidate_id=asn.id, user=w.user())
    assert (result.candidate.status, result.prefixes, result.target) == ("claimed", [], None)


def test_an_asn_whose_handle_overlaps_cloud_space_is_refused_whole(w, cloud):
    root = w.ours()
    asn = _asn_cand(w, root)
    ok = _cidr(w, root, 9)
    rejected_in_cloud = _record(w, root, "2001:db8:27a::/48", "cidr").candidate
    cd.reject(w.db, candidate_id=rejected_in_cloud.id, user=w.user(), reason="not ours")  # any status counts
    cloud("2001:db8:27a::/48")
    w.track_target(ok.value)
    targets_before = w.db.query(Target).count()
    events_before = w.db.query(ScopeCandidateEvent).count()
    with pytest.raises(cd.CandidateConflict, match="cloud"):
        cd.claim(w.db, candidate_id=asn.id, user=w.user())
    for c in (asn, ok):
        w.db.refresh(c)
        assert c.status == "open"
    assert w.db.query(Target).count() == targets_before
    assert w.db.query(ScopeCandidateEvent).count() == events_before


def test_a_conflicting_target_on_one_prefix_fails_the_whole_asn_claim(w):
    root = w.ours()
    eng = w.engagement()
    asn = _asn_cand(w, root)
    first, second, third = _cidr(w, root, 10), _cidr(w, root, 11), _cidr(w, root, 12)
    # whichever sorts last conflicts, so the earlier ones were already written when it fails
    ordered = sorted((first, second, third), key=lambda c: c.id)
    w.db.add(Target(id=uuid.uuid4(), type="cidr", value=ordered[-1].value, engagement_id=eng.id))
    w.db.commit()
    for c in ordered:
        w.track_target(c.value)
    events_before = w.db.query(ScopeCandidateEvent).count()
    with pytest.raises(cd.CandidateConflict, match=ordered[-1].value.split("/")[0]):
        cd.claim(w.db, candidate_id=asn.id, user=w.user())
    for c in (asn, *ordered):
        w.db.refresh(c)
        assert (c.status, c.target_id) == ("open", None)
    assert w.db.query(Target).filter(Target.value.in_([c.value for c in ordered])).count() == 1  # only the pre-existing one
    assert w.db.query(ScopeCandidateEvent).count() == events_before


# ── domain-only consumers ───────────────────────────────────────────────────


class _CountingFacts:
    def __init__(self):
        self.calls: list[str] = []

    def __call__(self, db, domain):
        self.calls.append(domain)
        return DomainFacts(
            domain=domain, ns=("ns1.fabrikam.com",), mx=(), spf_senders=(), spf_includes=(), registrant_org=None,
            registrant_org_folded=None, lookup_errors=(),
        )


def _domain() -> str:
    return f"org278-{hexid()}.example.net"


def test_the_verifier_runner_collects_facts_for_domains_only(w, monkeypatch):
    root = w.ours()
    anchor = w.candidate(root, value=_domain())
    cd.claim(w.db, candidate_id=anchor.id, user=w.user())
    w.track_target(anchor.value)
    domain = w.candidate(root, value=_domain())
    asn, cidr = _asn_cand(w, root), _cidr(w, root, 13)
    w.track_target(cidr.value)
    claimed_cidr = _cidr(w, root, 14)
    w.track_target(claimed_cidr.value)
    cd.claim(w.db, candidate_id=claimed_cidr.id, user=w.user())
    claimed_asn = _asn_cand(w, root, "AS64501")
    cd.claim(w.db, candidate_id=claimed_asn.id, user=w.user())
    fake = _CountingFacts()
    monkeypatch.setattr(runner, "_collect", fake)
    non_domain_values = {asn.value, cidr.value, claimed_cidr.value, claimed_asn.value}

    new = runner.verify_new_candidates([domain.id, asn.id, cidr.id])
    assert domain.value in fake.calls and anchor.value in fake.calls  # the path was reached
    assert new.pairs_checked == 1 and new.candidates_skipped == 2
    after = runner.verify_after_claim(anchor.id)
    assert after.pairs_checked == 1  # the one open domain; the open asn/cidr are not selected
    after_asn = runner.verify_after_claim(claimed_asn.id)
    assert (after_asn.pairs_checked, after_asn.candidates_skipped) == (0, 1)
    assert not (set(fake.calls) & non_domain_values)


def test_reverse_ip_ignores_a_claimed_cidr(w, monkeypatch):
    root = w.ours()
    c = _cidr(w, root, 15)
    w.track_target(c.value)
    claimed = cd.claim(w.db, candidate_id=c.id, user=w.user()).candidate

    def boom(*a, **k):
        raise AssertionError("reverse-IP must not run for a CIDR")

    from app.services.org_discovery import generators

    monkeypatch.setattr(generators, "_claimed_ips", boom)
    out = generators.record_reverse_ip(w.db, claimed=claimed)
    assert out.ips_checked == 0


def test_seed_and_connector_claims_refuse_non_domains(w):
    root = w.ours()
    c = _cidr(w, root, 0)
    with pytest.raises(ValueError, match="domain"):
        cd._claim_seed(w.db, candidate=c, root=root, engagement=None, user=w.user(), elsewhere_message="x")
    instance = type("I", (), {"bound_entity_id": root.id, "id": uuid.uuid4()})()
    with pytest.raises(cd.CandidateConflict, match="only claim a domain"):
        cd.claim_by_connector(w.db, candidate=c, instance=instance, target=None)
    w.db.rollback()
    w.db.refresh(c)
    assert c.status == "open"


# ── API ─────────────────────────────────────────────────────────────────────


def _list(w, root, headers, **params):
    r = client.get(f"/api/organizations/{root.id}/candidates", params={"status": "all", **params}, headers=headers)
    return r


def test_listing_defaults_to_domains_and_kind_selects_the_rest(w):
    root = w.ours()
    dom = w.candidate(root, value=_domain())
    asn, cidr = _asn_cand(w, root), _cidr(w, root, 1)
    headers = w.headers()

    default = _list(w, root, headers)
    assert default.status_code == 200, default.text
    assert [i["id"] for i in default.json()["items"]] == [str(dom.id)]
    assert default.json()["items"][0]["rir"] is None
    asns = _list(w, root, headers, kind="asn").json()
    assert [(i["id"], i["kind"], i["rir"], i["rir_handle"]) for i in asns["items"]] == [(str(asn.id), "asn", "ripe", HANDLE)]
    cidrs = _list(w, root, headers, kind="cidr").json()
    assert [i["id"] for i in cidrs["items"]] == [str(cidr.id)] and cidrs["total"] == 1
    assert _list(w, root, headers, kind="email").status_code == 422
    assert _list(w, root, headers, kind="domain").json()["total"] == 1


def test_the_org_summary_and_list_count_domains_only(w):
    root = w.ours()
    w.candidate(root, value=_domain())
    _asn_cand(w, root)
    _cidr(w, root, 2)
    headers = w.headers()
    s = client.get(f"/api/organizations/{root.id}/summary", headers=headers)
    assert s.status_code == 200, s.text
    assert s.json()["to_review"] == 1
    listing = client.get("/api/organizations/", headers=headers, params={"limit": 1000}).json()
    mine = next(o for o in listing if o["id"] == str(root.id))
    assert mine["proposed"] == 1


def test_the_claim_route_reports_claimed_prefixes(w, monkeypatch):
    after_claim = []
    monkeypatch.setattr(runner, "verify_after_claim", lambda *a: after_claim.append(a))
    root = w.ours()
    asn = _asn_cand(w, root)
    p1, p2 = _cidr(w, root, 3), _cidr(w, root, 4)
    solo = _cidr(w, root, 5, handle="OTHER-HANDLE")
    dom = w.candidate(root, value=_domain())
    for c in (p1, p2, solo, dom):
        w.track_target(c.value)
    headers = w.headers()

    r = client.post(f"/api/organizations/candidates/{asn.id}/claim", json={}, headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["status"], body["kind"], body["claimed_prefixes"], body["target_id"]) == ("claimed", "asn", 2, None)
    assert after_claim == []  # nothing domain-shaped to verify against
    for c in (p1, p2):
        w.db.refresh(c)
        assert c.status == "claimed" and c.target_id is not None
    r = client.post(f"/api/organizations/candidates/{solo.id}/claim", json={}, headers=headers)
    assert (r.status_code, r.json()["claimed_prefixes"], r.json()["target_id"] is not None) == (200, 0, True)
    r = client.post(f"/api/organizations/candidates/{dom.id}/claim", json={}, headers=headers)
    assert (r.status_code, r.json()["claimed_prefixes"]) == (200, 0)
    assert after_claim == [(dom.id,)]  # the positive path: a domain claim still schedules it
    from app.models.audit import AuditLog

    w.db.rollback()
    rows = w.db.query(AuditLog).filter(AuditLog.detail["changes"]["candidate"].astext == str(asn.id)).all()
    assert len(rows) == 1
    assert sorted(rows[0].detail["changes"]["claimed_prefixes"]) == sorted([str(p1.id), str(p2.id)])


def test_the_claim_route_answers_409_for_cloud_space(w, cloud, monkeypatch):
    root = w.ours()
    c = _cidr(w, root, 6)
    cloud(c.value)
    r = client.post(f"/api/organizations/candidates/{c.id}/claim", json={}, headers=w.headers())
    assert r.status_code == 409 and "cloud" in r.json()["detail"]


# ── the cloud guard fails closed; a cascade IntegrityError rolls back ───────


def _counts(db):
    return db.query(Target).count(), db.query(ScopeCandidateEvent).count()


def test_a_cidr_claim_is_refused_until_the_cloud_dataset_is_loaded(w, meta):
    root = w.ours()
    c = _cidr(w, root, 1)
    w.track_target(c.value)
    meta.remove()
    before = _counts(w.db)
    with pytest.raises(cd.CandidateConflict, match="dataset has not been loaded"):
        cd.claim(w.db, candidate_id=c.id, user=w.user())
    w.db.refresh(c)
    assert (c.status, c.target_id) == ("open", None) and _counts(w.db) == before
    meta.add()  # control: the same claim, now that the dataset is loaded
    result = cd.claim(w.db, candidate_id=c.id, user=w.user())
    assert result.candidate.status == "claimed" and result.target.value == c.value


def test_an_asn_claim_is_refused_until_the_cloud_dataset_is_loaded(w, meta):
    root = w.ours()
    asn = _asn_cand(w, root)
    c = _cidr(w, root, 2)
    w.track_target(c.value)
    meta.remove()
    before = _counts(w.db)
    with pytest.raises(cd.CandidateConflict, match="dataset has not been loaded"):
        cd.claim(w.db, candidate_id=asn.id, user=w.user())
    for x in (asn, c):
        w.db.refresh(x)
        assert (x.status, x.target_id) == ("open", None)
    assert _counts(w.db) == before
    meta.add()
    result = cd.claim(w.db, candidate_id=asn.id, user=w.user())
    assert [p.candidate.id for p in result.prefixes] == [c.id]


def test_a_stale_but_loaded_dataset_still_counts_as_loaded(w, meta):
    root = w.ours()
    c = _cidr(w, root, 3)
    w.track_target(c.value)
    w.db.execute(text("UPDATE cloud_ranges_meta SET generated_at = now() - interval '30 days'"))
    w.db.commit()
    w.db.expire_all()
    assert cloud_ranges.dataset_state(w.db).stale is True
    assert cd.claim(w.db, candidate_id=c.id, user=w.user()).candidate.status == "claimed"


def test_an_integrity_error_inside_the_asn_cascade_rolls_back_as_a_conflict(w, monkeypatch):
    root = w.ours()
    asn = _asn_cand(w, root)
    first, second = _cidr(w, root, 4), _cidr(w, root, 5)
    for c in (first, second):
        w.track_target(c.value)
    real = cd._attach_or_create_target
    raced: list[str] = []

    def racing(db, **kw):
        target, created = real(db, **kw)
        if created and not raced:
            # Another session adds the same target value and commits before our flush.
            raced.append(kw["value"])
            other = SessionLocal()
            try:
                other.add(Target(id=uuid.uuid4(), type="cidr", value=kw["value"]))
                other.commit()
            finally:
                other.close()
        return target, created

    monkeypatch.setattr(cd, "_attach_or_create_target", racing)
    before_events = w.db.query(ScopeCandidateEvent).count()
    with pytest.raises(cd.CandidateConflict, match=r"claim was rolled back \(uq_targets_value\)"):
        cd.claim(w.db, candidate_id=asn.id, user=w.user())
    assert raced  # the path was reached
    for x in (asn, first, second):  # the session is usable and nothing was written
        w.db.refresh(x)
        assert (x.status, x.target_id) == ("open", None)
    assert w.db.query(ScopeCandidateEvent).count() == before_events
    assert [t.value for t in w.db.query(Target).filter(Target.value.in_([first.value, second.value])).all()] == raced
