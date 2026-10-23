"""The scope-candidate service (planning#277 S1a): strength, record_signal,
unlock, add_by_person, claim, reject.

Ports what the former candidate-domains suite covered and still applies
(normalisation, the extractor, quote rules, claim locking, target conflicts,
the abandoned engagement, the single-commit rollback, the gate denying a
pre_close target) and adds the signal model's own behaviour. Where the old
suite said "proposed/accepted" this one says "open/claimed".

Run with:  scripts/test.sh app/tests/test_org_discovery_service.py
"""

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app.connectors.base import DiscoveredAsset
from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.authorisation_decision import AuthorisationDecision
from app.models.evidence import EvidenceFetch
from app.models.scope_candidate import ScopeCandidate, ScopeCandidateEvent, ScopeSignal
from app.models.org_entity import OrgEntity
from app.models.target import Target, TargetType
from app.models.target_asset_link import TargetAssetLink
from app.services import edgar_html, entity_relationship, target_service
from app.services import probe_authorisation as pa
from app.services.org_discovery import candidates as cd
from app.services.org_discovery import strength as strength_sql
from app.tests import _decision_log, _scope_candidates
from app.tests._org_world import World, hexid
from app.tests.test_org_discovery_schema import _insert_candidate, _insert_signal


@pytest.fixture
def w():
    world = World()
    try:
        yield world
    finally:
        world.close()


def _domain() -> str:
    return f"sc277-{hexid()}.example.com"


def _now():
    return datetime.now(timezone.utc)


def _record(w, root, value, signal_type="person_evidence", via=None, **kw):
    """`record_signal` for a person-anchored signal with fresh evidence."""
    ev = w.evidence_row()
    out = cd.record_signal(
        w.db, root_entity_id=root.id, value=value, signal_type=signal_type, anchor_kind="person",
        via_entity_id=(via or root).id, evidence_id=ev.id, quote=f"see {value} here", **kw,
    )
    w.db.commit()
    return out


def _strength(db, candidate_id):
    s = strength_sql.strength_subquery(candidate_ids=[candidate_id])
    row = db.execute(
        select(s.strength.label("strength"), s.proposable.label("proposable"),
               s.signal_count.label("signal_count"), s.strong_types.label("strong_types"))
        .select_from(ScopeCandidate)
        .outerjoin(s.subquery, s.candidate_id == ScopeCandidate.id)
        .where(ScopeCandidate.id == candidate_id)
    ).one()
    return row.strength, bool(row.proposable), row.signal_count, list(row.strong_types)


def _count(db, model, **filters):
    return db.query(model).filter_by(**filters).count()


# ── 1. the extractor (edgar_html.find_website_mentions) ────────────────────


def test_extractor_takes_the_domain_after_an_own_site_anchor_only():
    html = (
        "<html><body>"
        "<p>We sell to customers such as www.customer-one.example and partner.example.</p>"
        "<div><ix:nonNumeric name='dei:X'>Our website address is "
        "<a href='https://www.Acme-Widgets.example'>www.Acme-Widgets.example</a>.</ix:nonNumeric></div>"
        "<p>We make our reports available on our investor relations website at "
        "https://investors.acme-widgets.example/sec-filings , and the SEC maintains "
        "a website at www.sec.gov.</p>"
        "<p>The Company's website, www.sec.gov, is not ours.</p>"
        "</body></html>"
    )
    found = edgar_html.find_website_mentions(edgar_html.render_text_lines(html))
    domains = [d for d, _q in found]
    assert domains == ["acme-widgets.example", "investors.acme-widgets.example"]
    for d, q in found:
        assert d in q.lower(), (d, q)
    assert found[0][1] == "Our website address is www.Acme-Widgets.example ."


def test_extractor_does_not_split_on_the_domains_own_dots():
    lines = ["Available Information. Our internet address is www.example-co.example. Information on it is not part."]
    assert edgar_html.find_website_mentions(lines) == [
        ("example-co.example", "Our internet address is www.example-co.example.")
    ]


def test_extractor_returns_nothing_without_an_anchor():
    assert edgar_html.find_website_mentions(["Visit www.somebody.example for details."]) == []


# ── 2. normalisation ────────────────────────────────────────────────────────


@pytest.mark.parametrize("raw,expected", [
    ("WWW.Example.COM", "example.com"),
    ("bücher.example", "xn--bcher-kva.example"),
    ("sub.example.com", "sub.example.com"),
])
def test_normalise_domain(raw, expected):
    assert cd.normalise_domain(raw) == expected


@pytest.mark.parametrize("raw", ["", "not a domain", "192.0.2.1", "10.0.0.0/8", "nodot", "a..example.com",
                                 "https://www.example.com/path?q=1", "example.com:8080"])
def test_normalise_domain_refuses_non_hostnames(raw):
    with pytest.raises(cd.CandidateInvalid):
        cd.normalise_domain(raw)


# ── 3. strength, calculated in SQL ──────────────────────────────────────────


def _fresh_candidate(w, root):
    return _insert_candidate(w.db, root.id, value=_domain())


def _raw_signal(w, cid, via, signal_type):
    """A signal of a type with no generator, inserted directly to exercise the SQL."""
    ev = w.evidence_row()
    return _insert_signal(w.db, cid, via.id, signal_type=signal_type, evidence_id=ev.id, quote="a quote")


def test_strong_alone_is_proposable(w):
    root = w.ours()
    cid = _fresh_candidate(w, root)
    _raw_signal(w, cid, root, "connector_zone")
    assert _strength(w.db, cid)[:3] == ("strong", True, 1)
    assert _strength(w.db, cid)[3] == ["connector_zone"]


def test_two_supporting_signals_of_the_same_family_are_only_a_lead(w):
    root = w.ours()
    cid = _fresh_candidate(w, root)
    _raw_signal(w, cid, root, "mx_into_claimed")
    _raw_signal(w, cid, root, "spf_sender_shared")  # same family: mail
    assert _strength(w.db, cid)[:3] == ("lead", False, 2)


def test_supporting_signals_of_two_families_are_proposable(w):
    root = w.ours()
    cid = _fresh_candidate(w, root)
    _raw_signal(w, cid, root, "mx_into_claimed")
    _raw_signal(w, cid, root, "shared_vanity_ns")  # a second family: dns_hosting
    assert _strength(w.db, cid)[:3] == ("supporting", True, 2)


def test_context_signals_never_count(w):
    root = w.ours()
    cid = _fresh_candidate(w, root)
    for t in ("dmarc_exact_generic", "name_similarity", "ai_mention"):
        _raw_signal(w, cid, root, t)
    assert _strength(w.db, cid)[:3] == ("context", False, 3)
    # ...even beside one Supporting family (still a lead, not a proposal).
    _raw_signal(w, cid, root, "research_quote")
    assert _strength(w.db, cid)[:3] == ("lead", False, 4)


def test_a_candidate_with_no_signals_reads_as_context(w):
    root = w.ours()
    cid = _fresh_candidate(w, root)
    assert _strength(w.db, cid) == ("context", False, 0, [])


def test_strong_beats_everything_and_strong_types_are_distinct(w):
    root = w.ours()
    cid = _fresh_candidate(w, root)
    _raw_signal(w, cid, root, "connector_zone")
    _raw_signal(w, cid, root, "connector_zone")
    _raw_signal(w, cid, root, "mx_into_claimed")
    _raw_signal(w, cid, root, "name_similarity")
    strength, proposable, count, strong = _strength(w.db, cid)
    assert (strength, proposable, count, strong) == ("strong", True, 4, ["connector_zone"])


def test_the_default_affiliate_is_the_via_entity_of_the_best_signal(w):
    root = w.ours()
    a, b, c = w.child_of(root), w.child_of(root), w.child_of(root)
    cid = _fresh_candidate(w, root)
    _raw_signal(w, cid, a, "name_similarity")   # Context
    _raw_signal(w, cid, b, "mx_into_claimed")   # Supporting
    _raw_signal(w, cid, c, "connector_zone")    # Strong: wins
    expr = strength_sql.default_affiliate_expr(cid)
    assert w.db.execute(select(expr)).scalar_one() == c.id


# ── 4. record_signal ────────────────────────────────────────────────────────


def test_roots_of_follows_confirmed_parents_to_the_stop(w):
    root = w.ours()
    child = w.child_of(root)
    grandchild = w.child_of(child)
    assert [e.id for e in cd.roots_of(w.db, grandchild.id)] == [root.id]
    assert [e.id for e in cd.roots_of(w.db, root.id)] == [root.id]
    assert cd.roots_of(w.db, w.entity().id) == []  # no relationship anywhere: no root


def test_record_signal_creates_the_candidate_and_the_signal(w):
    root = w.ours()
    d = _domain()
    out = _record(w, root, d)
    assert (out.outcome, out.created_candidate, out.created_signal, out.unlocked) == ("recorded", True, True, False)
    assert (out.candidate.root_entity_id, out.candidate.value, out.candidate.status) == (root.id, d, "open")
    assert out.signal.signal_type == "person_evidence"


def test_a_second_signal_reuses_the_candidate_and_a_resighting_only_moves_last_seen(w):
    root = w.ours()
    d = _domain()
    ev = w.evidence_row()
    kw = dict(root_entity_id=root.id, value=d, signal_type="person_evidence", anchor_kind="person",
              via_entity_id=root.id, evidence_id=ev.id, quote=f"see {d}")
    first = cd.record_signal(w.db, **kw)
    w.db.commit()
    seen_first, seen_last = first.signal.first_seen_at, first.signal.last_seen_at
    again = cd.record_signal(w.db, **kw)  # the same route, the same evidence
    w.db.commit()
    assert (again.created_candidate, again.created_signal) == (False, False)
    assert again.signal.id == first.signal.id
    w.db.refresh(again.signal)
    assert again.signal.first_seen_at == seen_first and again.signal.last_seen_at > seen_last
    other = _record(w, root, d)  # new evidence: a new signal on the same candidate
    assert (other.created_candidate, other.created_signal, other.candidate.id) == (False, True, first.candidate.id)
    assert _count(w.db, ScopeCandidate, root_entity_id=root.id) == 1


def test_a_context_signal_on_an_unknown_domain_creates_nothing(w):
    root = w.ours()
    d = _domain()
    out = _record(w, root, d, signal_type="name_similarity")
    assert out.outcome == "skipped_context_only" and out.candidate is None
    assert _count(w.db, ScopeCandidate, root_entity_id=root.id) == 0
    assert w.db.query(ScopeSignal).filter(ScopeSignal.via_entity_id == root.id).count() == 0
    # ...but once a candidate exists, a Context signal is stored on it.
    _record(w, root, d)
    ctx = _record(w, root, d, signal_type="name_similarity")
    assert (ctx.outcome, ctx.created_signal) == ("recorded", True)


def test_a_supporting_signal_alone_creates_a_lead_candidate(w):
    root = w.ours()
    d = _domain()
    out = _record(w, root, d, signal_type="research_quote")
    assert out.created_candidate
    assert _strength(w.db, out.candidate.id)[:2] == ("lead", False)


def test_a_via_entity_outside_the_tree_is_refused(w):
    root = w.ours()
    stranger = w.entity()
    ev = w.evidence_row()
    d = _domain()
    with pytest.raises(cd.CandidateInvalid, match="tree"):
        cd.record_signal(
            w.db, root_entity_id=root.id, value=d, signal_type="person_evidence", anchor_kind="person",
            via_entity_id=stranger.id, evidence_id=ev.id, quote=d,
        )
    assert _count(w.db, ScopeCandidate, root_entity_id=root.id) == 0
    # A company that is a root of its own is not in THIS root's tree either.
    other = w.ours()
    with pytest.raises(cd.CandidateInvalid, match="tree"):
        cd.record_signal(
            w.db, root_entity_id=root.id, value=d, signal_type="person_evidence", anchor_kind="person",
            via_entity_id=other.id, evidence_id=ev.id, quote=d,
        )


def test_record_signal_input_rules(w):
    root = w.ours()
    d = _domain()
    ev = w.evidence_row()
    base = dict(root_entity_id=root.id, value=d, anchor_kind="person", via_entity_id=root.id)
    with pytest.raises(cd.CandidateInvalid, match="unknown signal type"):
        cd.record_signal(w.db, signal_type="vibes", evidence_id=ev.id, quote=d, **base)
    with pytest.raises(cd.CandidateInvalid, match="needs evidence"):
        cd.record_signal(w.db, signal_type="person_evidence", **base)
    with pytest.raises(cd.CandidateInvalid, match="together"):
        cd.record_signal(w.db, signal_type="person_evidence", evidence_id=ev.id, **base)
    with pytest.raises(cd.CandidateInvalid, match="must contain the domain"):
        cd.record_signal(w.db, signal_type="person_evidence", evidence_id=ev.id, quote="something else", **base)
    with pytest.raises(cd.CandidateInvalid, match="longer than"):
        cd.record_signal(w.db, signal_type="person_evidence", evidence_id=ev.id, quote=d + "x" * 2_001, **base)
    with pytest.raises(cd.CandidateInvalid, match="not a domain"):
        cd.record_signal(w.db, signal_type="person_evidence", evidence_id=ev.id, quote="x",
                         **{**base, "value": "192.0.2.1"})
    # case-insensitive containment is accepted
    assert cd.record_signal(w.db, signal_type="person_evidence", evidence_id=ev.id, quote=d.upper(), **base).outcome == "recorded"


def test_a_filer_filing_anchor_needs_a_confirmed_filer_in_the_tree(w):
    root = w.ours()
    filer = w.child_of(root)
    ev = w.evidence_row()
    d = _domain()
    kw = dict(root_entity_id=root.id, value=d, signal_type="filer_10k_website", anchor_kind="filer_filing",
              via_entity_id=filer.id, evidence_id=ev.id, quote=f"Our website is {d}")
    with pytest.raises(cd.CandidateInvalid, match="no CIK"):
        cd.record_signal(w.db, anchor_entity_id=filer.id, **kw)
    filer.cik = "0000000042"
    w.db.commit()
    with pytest.raises(cd.CandidateInvalid, match="needs the filer"):
        cd.record_signal(w.db, **kw)
    outsider = w.entity()
    outsider.cik = "0000000043"
    w.db.commit()
    with pytest.raises(cd.CandidateInvalid, match="tree"):
        cd.record_signal(w.db, anchor_entity_id=outsider.id, **kw)
    assert cd.record_signal(w.db, anchor_entity_id=filer.id, **kw).created_signal  # the path is reachable
    w.db.commit()


def test_a_claimed_candidate_anchor_must_already_be_claimed(w):
    root = w.ours()
    anchor = w.candidate(root)
    ev = w.evidence_row()
    d = _domain()
    kw = dict(root_entity_id=root.id, value=d, signal_type="redirect_to_claimed", anchor_kind="claimed_candidate",
              anchor_candidate_id=anchor.id, via_entity_id=root.id, evidence_id=ev.id, quote=d)
    with pytest.raises(cd.CandidateInvalid, match="claimed"):
        cd.record_signal(w.db, **kw)
    result = cd.claim(w.db, candidate_id=anchor.id, user=w.user())
    w.track_target(result.target.value)
    out = cd.record_signal(w.db, **kw)  # chained on a claimed candidate: accepted
    w.db.commit()
    assert out.created_signal and out.signal.anchor_candidate_id == anchor.id


# ── 5. unlock ───────────────────────────────────────────────────────────────


def _rejected_candidate(w, root, reason="not ours"):
    c = w.candidate(root)  # one Strong signal: person_evidence
    cd.reject(w.db, candidate_id=c.id, user=w.user(), reason=reason)
    w.db.refresh(c)
    assert (c.status, c.rejected_strong_types) == ("rejected", ["person_evidence"])  # the precondition
    return c


def test_a_new_strong_signal_type_unlocks_a_rejected_candidate(w):
    root = w.ours()
    c = _rejected_candidate(w, root, reason="looks like a vendor")
    out = cd.record_signal(
        w.db, root_entity_id=root.id, value=c.value, signal_type="admin_seed", anchor_kind="person",
        via_entity_id=root.id,
    )
    w.db.commit()
    assert (out.created_signal, out.unlocked) == (True, True)
    w.db.refresh(c)
    assert (c.status, c.rejection_reason, c.rejected_strong_types, c.decided_at, c.decided_by_id) == (
        "open", None, None, None, None,
    )
    ev = w.db.query(ScopeCandidateEvent).filter_by(candidate_id=c.id, event="unlocked").one()
    assert (ev.reason, ev.signal_id) == ("looks like a vendor", out.signal.id)
    assert [e.event for e in w.db.query(ScopeCandidateEvent).filter_by(candidate_id=c.id).order_by(
        ScopeCandidateEvent.at, ScopeCandidateEvent.id)] == ["rejected", "unlocked"]


def test_a_strong_type_that_was_present_at_rejection_does_not_unlock(w):
    root = w.ours()
    c = _rejected_candidate(w, root)
    before = _count(w.db, ScopeSignal, candidate_id=c.id)
    out = _record(w, root, c.value, signal_type="person_evidence")  # same type, NEW evidence
    assert out.created_signal  # the path was reached: a new signal row exists
    assert _count(w.db, ScopeSignal, candidate_id=c.id) == before + 1
    w.db.refresh(c)
    assert (c.status, out.unlocked) == ("rejected", False)
    assert _count(w.db, ScopeCandidateEvent, candidate_id=c.id, event="unlocked") == 0


def test_a_supporting_signal_does_not_unlock(w):
    root = w.ours()
    c = _rejected_candidate(w, root)
    out = _record(w, root, c.value, signal_type="research_quote")
    assert out.created_signal and out.signal.id is not None
    assert _count(w.db, ScopeSignal, candidate_id=c.id, signal_type="research_quote") == 1
    w.db.refresh(c)
    assert (c.status, out.unlocked) == ("rejected", False)


def test_a_resighted_strong_signal_does_not_unlock_either(w):
    """Even a type that was NOT present at rejection must be NEWLY inserted
    to unlock: re-seeing it later is not a new reason."""
    root = w.ours()
    c = _rejected_candidate(w, root)
    kw = dict(root_entity_id=root.id, value=c.value, signal_type="admin_seed", anchor_kind="person",
              via_entity_id=root.id)
    assert cd.record_signal(w.db, **kw).unlocked  # first sight unlocks
    w.db.commit()
    cd.reject(w.db, candidate_id=c.id, user=w.user(), reason="again")
    again = cd.record_signal(w.db, **kw)  # the same route seen again
    w.db.commit()
    assert (again.created_signal, again.unlocked) == (False, False)
    w.db.refresh(c)
    assert c.status == "rejected" and set(c.rejected_strong_types) == {"person_evidence", "admin_seed"}


def test_a_signal_never_changes_a_claimed_candidate(w):
    root = w.ours()
    c = w.candidate(root)
    result = cd.claim(w.db, candidate_id=c.id, user=w.user())
    w.track_target(result.target.value)
    out = cd.record_signal(
        w.db, root_entity_id=root.id, value=c.value, signal_type="admin_seed", anchor_kind="person",
        via_entity_id=root.id,
    )
    w.db.commit()
    assert out.created_signal and not out.unlocked
    w.db.refresh(c)
    assert c.status == "claimed"


# ── 6. add_by_person (ported from add_manual) ───────────────────────────────


def test_add_by_person_stores_person_supplied_evidence_and_a_strong_signal(w):
    root = w.ours()
    admin = w.user()
    d = _domain()
    excerpt = f"Press release. The acquired business trades at https://www.{d}/about. More text."
    c = cd.add_by_person(
        w.db, root_entity_id=root.id, via_entity_id=root.id, domain=f"WWW.{d.upper()}",
        source_url="https://news.example.test/item", excerpt=excerpt, quote=f"trades at https://www.{d}/about",
        user=admin,
    )
    assert (c.value, c.status, c.root_entity_id) == (d, "open", root.id)
    sig = w.db.query(ScopeSignal).filter_by(candidate_id=c.id).one()
    assert (sig.signal_type, sig.anchor_kind, sig.anchor_user_id, sig.via_entity_id) == (
        "person_evidence", "person", admin.id, root.id,
    )
    fetch = w.db.get(EvidenceFetch, sig.evidence_id)
    w.evidence.append(fetch.id)
    assert (fetch.origin, fetch.source_url) == ("person_supplied", "https://news.example.test/item")
    assert _strength(w.db, c.id)[:2] == ("strong", True)


@pytest.mark.parametrize("quote,excerpt_has_quote,message", [
    ("not in the excerpt", False, "verbatim"),
    ("trades at", True, "must contain the domain"),
])
def test_add_by_person_refuses_unsupported_quotes(w, quote, excerpt_has_quote, message):
    root = w.ours()
    d = _domain()
    excerpt = f"The business trades at {d}." if excerpt_has_quote else f"Something about {d}."
    with pytest.raises(cd.CandidateInvalid, match=message):
        cd.add_by_person(
            w.db, root_entity_id=root.id, via_entity_id=root.id, domain=d, source_url="https://news.example.test/x",
            excerpt=excerpt, quote=quote, user=w.user(),
        )
    assert _count(w.db, ScopeCandidate, root_entity_id=root.id) == 0


@pytest.mark.parametrize("source_url", ["ftp://x.example/a", "not a url", "https://u:p@x.example/a", ""])
def test_add_by_person_needs_an_http_source_url(w, source_url):
    root = w.ours()
    d = _domain()
    with pytest.raises(cd.CandidateInvalid, match="source_url"):
        cd.add_by_person(
            w.db, root_entity_id=root.id, via_entity_id=root.id, domain=d, source_url=source_url,
            excerpt=f"at {d}", quote=f"at {d}", user=w.user(),
        )


def test_add_by_person_refuses_a_company_outside_the_tree_and_an_unknown_root(w):
    root = w.ours()
    d = _domain()
    kw = dict(domain=d, source_url="https://news.example.test/y", excerpt=f"at {d}", quote=f"at {d}", user=w.user())
    with pytest.raises(cd.CandidateInvalid, match="tree"):
        cd.add_by_person(w.db, root_entity_id=root.id, via_entity_id=w.entity().id, **kw)
    with pytest.raises(cd.CandidateNotFound):
        cd.add_by_person(w.db, root_entity_id=uuid.uuid4(), via_entity_id=root.id, **kw)


def test_adding_a_domain_that_exists_adds_a_signal_not_a_conflict(w):
    root = w.ours()
    c = w.candidate(root)
    again = cd.add_by_person(
        w.db, root_entity_id=root.id, via_entity_id=root.id, domain=c.value,
        source_url="https://news.example.test/y", excerpt=f"at {c.value}", quote=f"at {c.value}", user=w.user(),
    )
    w.evidence.extend(s.evidence_id for s in w.db.query(ScopeSignal).filter_by(candidate_id=c.id))
    assert again.id == c.id
    assert _count(w.db, ScopeCandidate, root_entity_id=root.id) == 1
    assert _count(w.db, ScopeSignal, candidate_id=c.id) == 2


# ── 7. claim ────────────────────────────────────────────────────────────────


def test_claim_refuses_a_lead(w):
    root = w.ours()
    out = _record(w, root, _domain(), signal_type="research_quote")  # one Supporting family
    with pytest.raises(cd.CandidateConflict, match="not enough evidence to claim"):
        cd.claim(w.db, candidate_id=out.candidate.id, user=w.user())
    assert w.db.query(Target).filter(Target.value == out.candidate.value).count() == 0
    w.db.refresh(out.candidate)
    assert out.candidate.status == "open"


def test_claim_accepts_a_candidate_with_two_supporting_families(w):
    root = w.ours()
    out = _record(w, root, _domain(), signal_type="research_quote")
    _record(w, root, out.candidate.value, signal_type="shared_vanity_ns")
    result = cd.claim(w.db, candidate_id=out.candidate.id, user=w.user())
    w.track_target(result.target.value)
    assert result.candidate.status == "claimed"


def test_claim_into_an_ours_root_goes_to_the_estate_attributed_to_the_default_affiliate(w):
    root = w.ours()
    child = w.child_of(root)
    c = w.candidate(root, via=child)
    admin = w.user()
    result = cd.claim(w.db, candidate_id=c.id, user=admin)
    w.track_target(result.target.value)
    t, c2 = result.target, result.candidate
    assert result.created is True
    assert (t.engagement_id, t.entity_id, t.value, t.verified, t.source_type) == (None, child.id, c.value, True, "candidate_domain")
    assert (c2.status, c2.accepted_into, c2.engagement_id, c2.affiliated_entity_id, c2.target_id, c2.decided_by_id) == (
        "claimed", "estate", None, child.id, t.id, admin.id,
    )
    ev = w.db.query(ScopeCandidateEvent).filter_by(candidate_id=c.id, event="claimed").one()
    assert ev.user_id == admin.id


def test_claim_into_an_ma_root_goes_to_its_engagement(w):
    root, eng = w.deal()
    c = w.candidate(root)
    result = cd.claim(w.db, candidate_id=c.id, user=w.user())
    w.track_target(result.target.value)
    assert (result.target.engagement_id, result.candidate.accepted_into, result.candidate.engagement_id) == (
        eng.id, "engagement", eng.id,
    )


def test_an_explicit_affiliate_wins_over_the_default_and_must_be_in_the_tree(w):
    root = w.ours()
    via, chosen = w.child_of(root), w.child_of(root)
    c = w.candidate(root, via=via)
    with pytest.raises(cd.CandidateInvalid, match="tree"):
        cd.claim(w.db, candidate_id=c.id, user=w.user(), affiliated_entity_id=w.entity().id)
    w.db.refresh(c)
    assert c.status == "open"  # refused, so nothing changed
    result = cd.claim(w.db, candidate_id=c.id, user=w.user(), affiliated_entity_id=chosen.id)
    w.track_target(result.target.value)
    assert (result.target.entity_id, result.candidate.affiliated_entity_id) == (chosen.id, chosen.id)


def test_claim_blocks_on_an_unset_root_and_on_an_abandoned_deal(w):
    root, eng = w.deal()
    c = w.candidate(root)
    abandoned = w.db.get(type(eng), eng.id)
    abandoned.posture = "abandoned"
    w.db.commit()
    with pytest.raises(cd.CandidateConflict, match="abandoned"):
        cd.claim(w.db, candidate_id=c.id, user=w.user())
    # Unset: the relationship cleared after the candidate existed.
    root2 = w.ours()
    c2 = w.candidate(root2)
    entity_relationship.clear(w.db, entity_id=root2.id, may_clear_ours=True)
    with pytest.raises(cd.CandidateConflict, match="relationship first"):
        cd.claim(w.db, candidate_id=c2.id, user=w.user())
    assert w.db.query(Target).filter(Target.value.in_([c.value, c2.value])).count() == 0


def test_claim_with_two_live_engagements_is_ambiguous(w):
    root, _first = w.deal()
    w.engagement("pre_close", subject=root)
    c = w.candidate(root)
    with pytest.raises(cd.CandidateConflict, match="ambiguous"):
        cd.claim(w.db, candidate_id=c.id, user=w.user())


def test_a_decided_candidate_cannot_be_claimed_again(w):
    root = w.ours()
    c = w.candidate(root)
    first = cd.claim(w.db, candidate_id=c.id, user=w.user())
    w.track_target(first.target.value)
    with pytest.raises(cd.CandidateConflict, match="already claimed"):
        cd.claim(w.db, candidate_id=c.id, user=w.user())
    with pytest.raises(cd.CandidateConflict, match="already claimed"):
        cd.reject(w.db, candidate_id=c.id, user=w.user(), reason="late")
    with pytest.raises(cd.CandidateNotFound):
        cd.claim(w.db, candidate_id=uuid.uuid4(), user=w.user())


def test_claim_never_goes_through_ensure_pending(w, monkeypatch):
    """`ensure_pending` commits a target with NO engagement first: an
    unrestricted window. Spy on it: claim must not call it at all."""
    def _boom(*a, **k):
        raise AssertionError("claim called ensure_pending")

    monkeypatch.setattr(target_service, "ensure_pending", _boom)
    root, eng = w.deal()
    c = w.candidate(root)
    result = cd.claim(w.db, candidate_id=c.id, user=w.user())
    w.track_target(result.target.value)
    assert result.target.engagement_id == eng.id


def test_a_failed_claim_leaves_no_target_and_an_open_candidate(w):
    """The target insert and the decision share one commit. A user id with no
    `users` row fails that commit on its FK; nothing may survive."""
    root, _eng = w.deal()
    c = w.candidate(root)

    class _Ghost:
        id = uuid.uuid4()

    with pytest.raises(cd.CandidateConflict, match="rolled back"):
        cd.claim(w.db, candidate_id=c.id, user=_Ghost())
    assert w.db.query(Target).filter(Target.value == c.value).count() == 0
    w.db.refresh(c)
    assert c.status == "open"
    assert _count(w.db, ScopeCandidateEvent, candidate_id=c.id, event="claimed") == 0


def test_an_owned_estate_target_is_a_conflict_and_is_left_unchanged(w):
    root, _eng = w.deal()
    c = w.candidate(root)
    owned = Target(id=uuid.uuid4(), type=TargetType.DOMAIN.value, value=c.value)
    w.db.add(owned)
    w.db.commit()
    w.track_target(c.value)
    with pytest.raises(cd.CandidateConflict, match="outside this destination"):
        cd.claim(w.db, candidate_id=c.id, user=w.user())
    w.db.refresh(owned)
    w.db.refresh(c)
    assert (owned.engagement_id, owned.entity_id, c.status) == (None, None, "open")


def test_a_target_attributed_to_another_entity_is_a_conflict(w):
    root = w.ours()
    other = w.child_of(root)
    c = w.candidate(root)
    existing = Target(id=uuid.uuid4(), type=TargetType.DOMAIN.value, value=c.value, entity_id=other.id)
    w.db.add(existing)
    w.db.commit()
    w.track_target(c.value)
    with pytest.raises(cd.CandidateConflict, match="different entity"):
        cd.claim(w.db, candidate_id=c.id, user=w.user(), affiliated_entity_id=root.id)


def test_an_existing_target_in_the_same_destination_is_attached(w):
    root, eng = w.deal()
    c = w.candidate(root)
    same = Target(id=uuid.uuid4(), type=TargetType.DOMAIN.value, value=c.value, engagement_id=eng.id)
    w.db.add(same)
    w.db.commit()
    w.track_target(c.value)
    result = cd.claim(w.db, candidate_id=c.id, user=w.user())
    assert (result.created, result.target.id, result.target.entity_id) == (False, same.id, root.id)
    assert w.db.query(Target).filter(Target.value == c.value).count() == 1


def test_deleting_the_claimed_target_does_not_break_the_row(w):
    """`target_id` is ON DELETE SET NULL, performed by Postgres as an UPDATE
    the guard trigger also sees: it must allow it."""
    root, eng = w.deal()
    c = w.candidate(root)
    result = cd.claim(w.db, candidate_id=c.id, user=w.user())
    w.db.query(Target).filter(Target.id == result.target.id).delete(synchronize_session=False)
    w.db.commit()
    w.db.refresh(c)
    assert (c.status, c.target_id, c.engagement_id) == ("claimed", None, eng.id)


def test_a_claim_under_pre_close_creates_a_target_the_gate_denies(w):
    root, eng = w.deal()
    c = w.candidate(root)
    admin = w.user()
    result = cd.claim(w.db, candidate_id=c.id, user=admin)
    w.track_target(result.target.value)
    target = result.target
    assert (target.engagement_id, target.entity_id, target.value) == (eng.id, root.id, c.value)

    run_id = uuid.uuid4()
    asset_value = f"sc277-asset-{hexid()}"
    asset = None
    try:
        # Entry point 1: domain-shaped discovery (#196). An active
        # (`target_infra`) tool is denied on posture; a `silent` one is not.
        assert pa.authorise_discovery(
            w.db, observer_slug="dnsrecon", target_row=target, domain=target.value, scan_run_id=run_id
        ) is False
        row = (
            w.db.query(AuthorisationDecision)
            .filter(AuthorisationDecision.evidence_snapshot["scan_run_id"].astext == str(run_id))
            .one()
        )
        assert row.rule_fired == "posture:passive_only"
        assert pa.authorise_discovery(
            w.db, observer_slug="subfinder", target_row=target, domain=target.value, scan_run_id=run_id
        ) is True

        # Entry point 2: asset-shaped (#193). An asset linked to the new
        # target, even at `direct_addressable`, is denied the port sweep.
        asset = AssetCanonical(
            id=uuid.uuid4(), asset_type="ip_address", value=asset_value, first_seen_at=_now(), last_seen_at=_now()
        )
        w.db.add(asset)
        w.db.commit()
        w.db.add(AssetState(asset_canonical_id=asset.id, attributes={"probe_class": "direct_addressable"}, projected_at=_now()))
        w.db.add(TargetAssetLink(target_id=target.id, asset_canonical_id=asset.id))
        w.db.commit()

        class _Naabu:
            observer = "naabu"

        gate = pa.authorise_probes(
            w.db, connector_id="naabu", connector=_Naabu(),
            assets=[DiscoveredAsset(asset_type="ip_address", value=asset_value)], scope={}, scan_run_id=run_id,
        )
        permission = gate.permissions[("ip_address", asset_value)]
        assert permission.allowed is False
        assert permission.rule_fired == "posture:passive_only"
    finally:
        _decision_log.cleanup_for_run(run_id)
        if asset is not None:
            w.db.query(AuthorisationDecision).filter(
                AuthorisationDecision.asset_canonical_id == asset.id
            ).delete(synchronize_session=False)
            w.db.query(TargetAssetLink).filter(TargetAssetLink.asset_canonical_id == asset.id).delete(
                synchronize_session=False
            )
            w.db.query(AssetState).filter(AssetState.asset_canonical_id == asset.id).delete(synchronize_session=False)
            w.db.query(AssetCanonical).filter(AssetCanonical.id == asset.id).delete(synchronize_session=False)
            w.db.commit()


# ── 8. reject ───────────────────────────────────────────────────────────────


def test_reject_records_who_why_and_the_strong_types(w):
    root = w.ours()
    c = w.candidate(root)
    admin = w.user()
    rejected = cd.reject(w.db, candidate_id=c.id, user=admin, reason="  a vendor, not us  ")
    assert (rejected.status, rejected.decided_by_id, rejected.rejection_reason) == ("rejected", admin.id, "a vendor, not us")
    assert rejected.decided_at is not None
    assert rejected.rejected_strong_types == ["person_evidence"]
    ev = w.db.query(ScopeCandidateEvent).filter_by(candidate_id=c.id, event="rejected").one()
    assert (ev.user_id, ev.reason) == (admin.id, "a vendor, not us")


def test_reject_with_no_strong_signal_stores_an_empty_array(w):
    root = w.ours()
    out = _record(w, root, _domain(), signal_type="research_quote")
    rejected = cd.reject(w.db, candidate_id=out.candidate.id, user=w.user(), reason="no")
    assert rejected.rejected_strong_types == []


@pytest.mark.parametrize("reason,message", [("", "required"), ("   ", "required"), ("x" * 501, "longer than")])
def test_reject_validates_the_reason(w, reason, message):
    root = w.ours()
    c = w.candidate(root)
    with pytest.raises(cd.CandidateInvalid, match=message):
        cd.reject(w.db, candidate_id=c.id, user=w.user(), reason=reason)
    w.db.refresh(c)
    assert c.status == "open"


def test_a_rejected_candidate_cannot_be_rejected_or_claimed(w):
    root = w.ours()
    c = _rejected_candidate(w, root)
    with pytest.raises(cd.CandidateConflict, match="already rejected"):
        cd.reject(w.db, candidate_id=c.id, user=w.user(), reason="again")
    with pytest.raises(cd.CandidateConflict, match="already rejected"):
        cd.claim(w.db, candidate_id=c.id, user=w.user())
    with pytest.raises(cd.CandidateNotFound):
        cd.reject(w.db, candidate_id=uuid.uuid4(), user=w.user(), reason="x")


def test_the_cleanup_helper_leaves_nothing_behind(w):
    """The test hygiene itself: `purge` removes candidates, signals and
    events under an entity (the events trigger is disabled for it and
    restored)."""
    root = w.ours()
    cid = _rejected_candidate(w, root).id
    assert w.db.query(ScopeCandidateEvent).filter(ScopeCandidateEvent.candidate_id == cid).count() == 1  # reached
    _scope_candidates.purge(w.db, entity_ids=[root.id])
    assert w.db.query(ScopeCandidate).filter(ScopeCandidate.id == cid).count() == 0
    assert w.db.query(ScopeCandidateEvent).filter(ScopeCandidateEvent.candidate_id == cid).count() == 0
    from sqlalchemy import text
    enabled = w.db.execute(text(
        "select tgenabled from pg_trigger where tgname = 'trg_scope_candidate_events_append_only'"
    )).scalar_one()
    assert enabled == "O"  # 'O' = enabled


# ── 9. races and serialisation (review fixes F1, F2) ────────────────────────


def test_a_reject_that_commits_during_record_signal_is_still_unlocked_by_the_new_type(w, monkeypatch):
    """Two real sessions. A reads the candidate as OPEN; B rejects and commits
    (its `rejected_strong_types` cannot include a type A has not committed);
    A then records a new Strong type. The unlock must lock and re-check
    rather than trust A's stale read."""
    root = w.ours()
    c = w.candidate(root)
    cid, value = c.id, c.value
    reject_by = SimpleNamespace(id=w.user().id)
    other = SessionLocal()
    real_now = cd._now
    fired: list[bool] = []

    def hook():
        # `_now()` is evaluated building the signal INSERT: after the candidate
        # was read (open), before the unlock check.
        if not fired:
            fired.append(True)
            cd.reject(other, candidate_id=cid, user=reject_by, reason="rejected in the gap")
        return real_now()

    monkeypatch.setattr(cd, "_now", hook)
    try:
        out = cd.record_signal(
            w.db, root_entity_id=root.id, value=value, signal_type="admin_seed", anchor_kind="person",
            via_entity_id=root.id,
        )
        w.db.commit()
    finally:
        other.close()
    assert fired == [True]                                   # the interleaving happened
    assert _count(w.db, ScopeCandidateEvent, candidate_id=cid, event="rejected") == 1
    assert (out.created_signal, out.unlocked) == (True, True)
    w.db.refresh(c)
    assert (c.status, c.rejection_reason) == ("open", None)
    ev = w.db.query(ScopeCandidateEvent).filter_by(candidate_id=cid, event="unlocked").one()
    assert (ev.reason, ev.signal_id) == ("rejected in the gap", out.signal.id)


def _resolve_spy(monkeypatch, on_second):
    real = cd.entity_relationship.resolve
    calls: list = []

    def fake(db, entity_id):
        calls.append(entity_id)
        res = real(db, entity_id)
        return on_second(res) if len(calls) == 2 else res

    monkeypatch.setattr(cd.entity_relationship, "resolve", fake)
    return calls


@pytest.mark.parametrize("what", ["visited_only", "stops_only"])
def test_claim_refuses_when_the_affiliates_walk_changes_under_the_lock(w, monkeypatch, what):
    """Each half of the comparison is pinned on its own: a walk that read a
    different set of companies, and one that stopped at different relationships."""
    from app.services.entity_relationship import Resolution, Stop

    root = w.ours()
    child = w.child_of(root)
    c = w.candidate(root, via=child)

    def changed(res):
        if what == "visited_only":
            return Resolution(status=res.status, estate=res.estate, stops=list(res.stops),
                              visited=res.visited + [uuid.uuid4()])
        return Resolution(status=res.status, estate=res.estate, visited=list(res.visited),
                          stops=[Stop(entity_id=s.entity_id, relationship="ma_target", depth=s.depth) for s in res.stops])

    calls = _resolve_spy(monkeypatch, changed)
    with pytest.raises(cd.CandidateConflict, match="changed while claiming"):
        cd.claim(w.db, candidate_id=c.id, user=w.user())
    assert len(calls) == 2                                   # both walks ran: the check was REACHED
    assert w.db.query(Target).filter(Target.value == c.value).count() == 0
    w.db.refresh(c)
    assert c.status == "open"


def test_claim_locks_every_entity_the_affiliates_walk_read_plus_the_root(w, monkeypatch):
    root = w.ours()
    child = w.child_of(root)
    grandchild = w.child_of(child)
    c = w.candidate(root, via=grandchild)
    other = SessionLocal()
    probed: dict = {}

    def second(res):
        for eid in (grandchild.id, child.id, root.id):
            try:
                other.execute(select(OrgEntity.id).where(OrgEntity.id == eid).with_for_update(nowait=True)).all()
                probed[eid] = "free"
            except Exception as exc:  # lock_not_available
                probed[eid] = getattr(getattr(exc, "orig", None), "pgcode", "?")
            other.rollback()
        return res

    _resolve_spy(monkeypatch, second)
    try:
        result = cd.claim(w.db, candidate_id=c.id, user=w.user())
    finally:
        other.close()
    w.track_target(result.target.value)
    assert probed == {grandchild.id: "55P03", child.id: "55P03", root.id: "55P03"}  # all held by the claim
    assert result.candidate.status == "claimed" and result.target.entity_id == grandchild.id
