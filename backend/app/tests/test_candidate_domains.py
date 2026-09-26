"""Candidate domains (planning#216, L6): extractor, schema, service.

Every acceptance criterion on #216 maps to a test here, and each test
names the constraint or path it reaches — a test titled after a rule but
satisfied by a different constraint is the vacuous-test shape this suite
keeps catching (feedback_vacuous_tests).

Invented names and reserved TLDs only (`.example`, `.test`) — never a real
company or domain (feedback_real_customer_data). Rows are created and
deleted by id.

Run with:  pytest app/tests/test_candidate_domains.py
"""

import ast
import inspect
import uuid
from datetime import date, datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy.exc import IntegrityError, InternalError

from app.connectors.base import DiscoveredAsset
from app.core.database import SessionLocal
from app.models.asset_canonical import AssetCanonical
from app.models.asset_state import AssetState
from app.models.authorisation_decision import AuthorisationDecision
from app.models.candidate_domain import CandidateDomain
from app.models.evidence import EvidenceFetch
from app.models.observer import Observer
from app.models.target import Target, TargetType
from app.models.target_asset_link import TargetAssetLink
from app.models.user import User, UserRole
from app.services import candidate_domains as cd
from app.services import edgar_html, entity_graph, target_service
from app.services import probe_authorisation as pa
from app.tests import _decision_log
from app.tests._engagement import cleanup_engagement, make_engagement
from app.tests._entity_graph import (
    cleanup_entity,
    cleanup_evidence,
    cleanup_relation,
    make_entity,
    make_evidence,
    make_observer,
    cleanup_observer,
)


def _hex() -> str:
    return uuid.uuid4().hex[:10]


def _domain() -> str:
    return f"cd216-{_hex()}.example"


def _now():
    return datetime.now(timezone.utc)


# ── fixture: one throwaway world per test, torn down in FK order ───────────


class _World:
    def __init__(self):
        self.db = SessionLocal()
        self.candidates: list[uuid.UUID] = []
        self.targets: list[uuid.UUID] = []
        self.engagements: list[uuid.UUID] = []
        self.relations: list[uuid.UUID] = []
        self.entities: list[uuid.UUID] = []
        self.evidence: list[uuid.UUID] = []
        self.users: list[uuid.UUID] = []
        self.observers: list[uuid.UUID] = []

    def user(self, role: str = UserRole.ADMIN.value) -> User:
        u = User(
            id=uuid.uuid4(), email=f"cd216-{_hex()}@example.invalid", full_name="cd216 test",
            role=role, is_active=True,
        )
        self.db.add(u)
        self.db.commit()
        self.users.append(u.id)
        return u

    def entity(self):
        e = make_entity(self.db)
        self.entities.append(e.id)
        return e

    def engagement(self, posture: str = "pre_close", subject=None, **extra):
        if posture in ("day_0", "integrated"):
            extra.setdefault("authorised_at", _now())
            extra.setdefault("authorisation_reference", "cd216-ref")
        e = make_engagement(self.db, posture, subject_entity_id=subject.id if subject else None, **extra)
        self.engagements.append(e.id)
        return e

    def evidence_row(self, text: str = "filing text"):
        f = make_evidence(self.db, content=f"{text} {_hex()}".encode(), source_url=f"https://example.test/{_hex()}")
        self.evidence.append(f.id)
        return f

    def website_observer(self) -> Observer:
        return self.db.query(Observer).filter(Observer.name == "edgar_10k_website").one()

    def filing_candidate(self, entity, domain: str | None = None, filing_date: date = date(2020, 3, 1)):
        domain = domain or _domain()
        ev = self.evidence_row()
        cd.propose_from_filing(
            self.db, entity_id=entity.id, domain=domain, observer=self.website_observer(),
            evidence_id=ev.id, quote=f"Our website is www.{domain}.", filing_date=filing_date,
        )
        row = self.db.query(CandidateDomain).filter_by(entity_id=entity.id, domain=domain).one()
        self.candidates.append(row.id)
        return row

    def track_target_value(self, value: str) -> None:
        t = self.db.query(Target).filter(Target.value == value).one_or_none()
        if t is not None and t.id not in self.targets:
            self.targets.append(t.id)

    def close(self):
        db = self.db
        db.rollback()
        cand_evidence = [
            r.evidence_id for r in db.query(CandidateDomain).filter(CandidateDomain.id.in_(self.candidates)).all()
        ]
        db.query(CandidateDomain).filter(CandidateDomain.id.in_(self.candidates)).delete(synchronize_session=False)
        # Candidates created through other entities' ids (e.g. by an API) are
        # swept by entity too.
        more = db.query(CandidateDomain).filter(CandidateDomain.entity_id.in_(self.entities)).all()
        cand_evidence += [r.evidence_id for r in more]
        db.query(CandidateDomain).filter(CandidateDomain.entity_id.in_(self.entities)).delete(synchronize_session=False)
        db.query(Target).filter(Target.id.in_(self.targets)).delete(synchronize_session=False)
        db.query(Target).filter(Target.entity_id.in_(self.entities)).delete(synchronize_session=False)
        db.commit()
        for eid in self.engagements:
            cleanup_engagement(db, eid)
        for rid in self.relations:
            cleanup_relation(db, rid)
        for eid in self.entities:
            cleanup_entity(db, eid)
        for fid in set(self.evidence + cand_evidence):
            cleanup_evidence(db, fid)
        for oid in self.observers:
            cleanup_observer(db, oid)
        db.query(User).filter(User.id.in_(self.users)).delete(synchronize_session=False)
        db.commit()
        db.close()


@pytest.fixture
def w():
    world = _World()
    try:
        yield world
    finally:
        world.close()


def _raw_insert(db, **values):
    """A raw insert that bypasses the service — the DB constraints are
    what's under test."""
    base = dict(id=uuid.uuid4(), source="edgar_10k_website", status="proposed")
    base.update(values)
    db.execute(CandidateDomain.__table__.insert().values(**base))
    db.commit()
    return base["id"]


def _constraint(exc) -> str | None:
    return getattr(getattr(exc.orig, "diag", None), "constraint_name", None)


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
    # Anchor-gated: the customer/partner domains in ordinary prose never
    # appear; `.gov` is excluded even straight after an anchor.
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


# ── 2. no name → domain path (acceptance 1) ────────────────────────────────


def test_no_name_to_domain_path():
    """AST, not grep: neither the service nor the extractor nor the
    candidate API handlers read `legal_name` or accept a name-like
    parameter. A grep would also hit this sentence."""
    import app.api.entities as api

    service_tree = ast.parse(Path(cd.__file__).read_text(encoding="utf-8"))
    handler_sources = [
        inspect.getsource(f)
        for f in (
            api.list_candidate_domains, api.add_candidate_domain,
            api.accept_candidate_domain, api.reject_candidate_domain, api._to_candidate_response,
        )
    ]
    trees = [service_tree, ast.parse(inspect.getsource(edgar_html.find_website_mentions))]
    trees += [ast.parse(src) for src in handler_sources]
    for tree in trees:
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                assert node.attr != "legal_name", "candidate path reads an entity name"
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                params = [a.arg for a in node.args.args + node.args.kwonlyargs]
                assert not any(p in ("name", "legal_name", "company", "company_name") for p in params), (
                    node.name, params,
                )


# ── 3. DB-enforced evidence (acceptance 2) ─────────────────────────────────


def test_insert_without_evidence_is_refused_by_not_null(w):
    e = w.entity()
    obs = w.website_observer()
    with pytest.raises(IntegrityError) as exc:
        _raw_insert(w.db, entity_id=e.id, domain=_domain(), observer_id=obs.id, evidence_id=None, quote="x")
    assert exc.value.orig.pgcode == "23502"  # not_null_violation
    assert exc.value.orig.diag.column_name == "evidence_id"


def test_quote_that_does_not_contain_the_domain_is_refused(w):
    """Real evidence, wrong quote: a citation that never mentions the
    domain cannot carry a guessed domain in."""
    e = w.entity()
    ev = w.evidence_row()
    with pytest.raises(IntegrityError) as exc:
        _raw_insert(
            w.db, entity_id=e.id, domain=_domain(), observer_id=w.website_observer().id,
            evidence_id=ev.id, quote="Our website is www.something-else.example.",
        )
    assert _constraint(exc.value) == "ck_candidate_domains_quote_contains_domain"


@pytest.mark.parametrize(
    "domain,constraint",
    [
        ("www.cd216.example", "ck_candidate_domains_no_www"),
        ("Upper.example", "ck_candidate_domains_domain_shape"),
        ("https://cd216.example", "ck_candidate_domains_domain_shape"),
        ("192.0.2.1", "ck_candidate_domains_domain_shape"),
        ("nodot", "ck_candidate_domains_domain_shape"),
    ],
)
def test_domain_shape_checks(w, domain, constraint):
    e = w.entity()
    ev = w.evidence_row()
    with pytest.raises(IntegrityError) as exc:
        _raw_insert(
            w.db, entity_id=e.id, domain=domain, observer_id=w.website_observer().id,
            evidence_id=ev.id, quote=f"our site {domain}",
        )
    assert _constraint(exc.value) == constraint


def test_person_source_must_not_carry_an_observer(w):
    e = w.entity()
    ev = w.evidence_row()
    d = _domain()
    with pytest.raises(IntegrityError) as exc:
        _raw_insert(
            w.db, entity_id=e.id, domain=d, source="person", observer_id=w.website_observer().id,
            evidence_id=ev.id, quote=f"see {d}",
        )
    assert _constraint(exc.value) == "ck_candidate_domains_source_observer"


def test_accepted_without_engagement_is_refused(w):
    e = w.entity()
    ev = w.evidence_row()
    d = _domain()
    with pytest.raises(IntegrityError) as exc:
        _raw_insert(
            w.db, entity_id=e.id, domain=d, observer_id=w.website_observer().id, evidence_id=ev.id,
            quote=f"see {d}", status="accepted", decided_at=_now(),
        )
    assert _constraint(exc.value) == "ck_candidate_domains_engagement"


# ── 4. the guard trigger ───────────────────────────────────────────────────


def test_decided_row_cannot_be_demoted_or_redecided(w):
    e = w.entity()
    c = w.filing_candidate(e)
    cd.reject(w.db, candidate_id=c.id, user=w.user())
    for new_status in ("proposed", "accepted"):
        with pytest.raises(InternalError) as exc:
            w.db.execute(
                CandidateDomain.__table__.update().where(CandidateDomain.id == c.id).values(status=new_status)
            )
            w.db.commit()
        w.db.rollback()
        assert "cannot change once decided" in str(exc.value.orig)


def test_claimed_fields_are_immutable(w):
    e = w.entity()
    c = w.filing_candidate(e)
    other = w.evidence_row()
    for values in ({"domain": _domain()}, {"evidence_id": other.id}, {"quote": f"our site {c.domain} (edited)"}):
        with pytest.raises(InternalError) as exc:
            w.db.execute(CandidateDomain.__table__.update().where(CandidateDomain.id == c.id).values(**values))
            w.db.commit()
        w.db.rollback()
        assert "immutable" in str(exc.value.orig), values


# ── 5. propose_from_filing: dates widen, status never moves ────────────────


def test_resighting_widens_cited_dates_and_never_undoes_a_rejection(w):
    e = w.entity()
    d = _domain()
    c = w.filing_candidate(e, d, filing_date=date(2015, 3, 1))
    cd.reject(w.db, candidate_id=c.id, user=w.user())

    later = w.evidence_row()
    inserted = cd.propose_from_filing(
        w.db, entity_id=e.id, domain=d, observer=w.website_observer(), evidence_id=later.id,
        quote=f"Our website is {d}.", filing_date=date(2021, 2, 1),
    )
    assert inserted is False
    rows = w.db.query(CandidateDomain).filter_by(entity_id=e.id, domain=d).all()
    assert len(rows) == 1
    w.db.refresh(rows[0])
    assert rows[0].status == "rejected"
    assert rows[0].evidence_id == c.evidence_id  # first citation kept
    assert (rows[0].first_cited_on, rows[0].last_cited_on) == (date(2015, 3, 1), date(2021, 2, 1))


def test_propose_skips_a_quote_that_lacks_the_domain(w):
    e = w.entity()
    ev = w.evidence_row()
    assert cd.propose_from_filing(
        w.db, entity_id=e.id, domain=_domain(), observer=w.website_observer(), evidence_id=ev.id,
        quote="Our website is elsewhere.", filing_date=date(2020, 1, 1),
    ) is False
    assert w.db.query(CandidateDomain).filter_by(entity_id=e.id).count() == 0


# ── 6. manual add (C2) ─────────────────────────────────────────────────────


def test_manual_add_stores_person_supplied_evidence(w):
    e = w.entity()
    admin = w.user()
    d = _domain()
    excerpt = f"Press release. The acquired business trades at https://www.{d}/about. More text."
    c = cd.add_manual(
        w.db, entity_id=e.id, domain=f"WWW.{d.upper()}", source_url="https://news.example.test/item",
        excerpt=excerpt, quote=f"trades at https://www.{d}/about", user=admin,
    )
    w.candidates.append(c.id)
    assert (c.domain, c.source, c.observer_id, c.created_by_id) == (d, "person", None, admin.id)
    fetch = w.db.get(EvidenceFetch, c.evidence_id)
    assert fetch.origin == "person_supplied"
    assert fetch.source_url == "https://news.example.test/item"


@pytest.mark.parametrize(
    "quote,excerpt_has_quote,message",
    [
        ("not in the excerpt", False, "verbatim"),
        ("trades at", True, "must contain the domain"),
    ],
)
def test_manual_add_refuses_unsupported_quotes(w, quote, excerpt_has_quote, message):
    e = w.entity()
    d = _domain()
    excerpt = f"The business trades at {d}." if excerpt_has_quote else f"Something about {d}."
    with pytest.raises(cd.CandidateInvalid, match=message):
        cd.add_manual(
            w.db, entity_id=e.id, domain=d, source_url="https://news.example.test/x",
            excerpt=excerpt, quote=quote, user=w.user(),
        )
    assert w.db.query(CandidateDomain).filter_by(entity_id=e.id).count() == 0


def test_manual_add_duplicate_is_a_conflict(w):
    e = w.entity()
    c = w.filing_candidate(e)
    with pytest.raises(cd.CandidateConflict):
        cd.add_manual(
            w.db, entity_id=e.id, domain=c.domain, source_url="https://news.example.test/y",
            excerpt=f"at {c.domain}", quote=f"at {c.domain}", user=w.user(),
        )


# ── 7. accept under pre_close → the gate denies (acceptance 3) ─────────────


def test_accept_under_pre_close_creates_a_target_the_gate_denies(w):
    subject = w.entity()
    eng = w.engagement("pre_close", subject=subject)
    c = w.filing_candidate(subject)
    admin = w.user()

    result = cd.accept(w.db, candidate_id=c.id, engagement_id=eng.id, user=admin)
    w.targets.append(result.target.id)
    target = result.target
    assert result.created is True
    assert (target.engagement_id, target.entity_id, target.value) == (eng.id, subject.id, c.domain)
    assert (result.candidate.status, result.candidate.decided_by_id, result.candidate.target_id) == (
        "accepted", admin.id, target.id,
    )

    run_id = uuid.uuid4()
    asset_value = f"cd216-asset-{_hex()}"
    asset = None
    try:
        # Entry point 1 — domain-shaped discovery (#196): an active
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

        # Entry point 2 — asset-shaped (#193): an asset linked to the new
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


def test_accept_never_goes_through_ensure_pending(w, monkeypatch):
    """`ensure_pending` commits a target with NO engagement first — an
    unrestricted window. Spy on it: accept must not call it at all."""
    def _boom(*a, **k):
        raise AssertionError("accept called ensure_pending")

    monkeypatch.setattr(target_service, "ensure_pending", _boom)
    subject = w.entity()
    eng = w.engagement("pre_close", subject=subject)
    c = w.filing_candidate(subject)
    result = cd.accept(w.db, candidate_id=c.id, engagement_id=eng.id, user=w.user())
    w.targets.append(result.target.id)
    assert result.target.engagement_id == eng.id


def test_failed_accept_leaves_no_target(w):
    """The target insert and the decision share one commit. A user id with
    no `users` row fails that commit on its FK; nothing may survive."""
    subject = w.entity()
    eng = w.engagement("pre_close", subject=subject)
    c = w.filing_candidate(subject)

    class _Ghost:
        id = uuid.uuid4()

    with pytest.raises(cd.CandidateConflict, match="rolled back"):
        cd.accept(w.db, candidate_id=c.id, engagement_id=eng.id, user=_Ghost())
    assert w.db.query(Target).filter(Target.value == c.domain).count() == 0
    w.db.refresh(c)
    assert c.status == "proposed"


# ── 8. which engagement may receive a candidate (C3) ───────────────────────


def test_accept_requires_a_confirmed_hop_to_the_engagement_subject(w):
    parent = w.entity()
    child = w.entity()
    eng = w.engagement("pre_close", subject=parent)
    c = w.filing_candidate(child)
    admin = w.user()

    # No relation at all → refused.
    with pytest.raises(cd.CandidateConflict, match="confirmed"):
        cd.accept(w.db, candidate_id=c.id, engagement_id=eng.id, user=admin)

    # A PROPOSED relation is attention, not scope → still refused.
    observer = make_observer(w.db)
    w.observers.append(observer.id)
    ev = w.evidence_row()
    rel = entity_graph.assert_relation(
        w.db, subject_id=parent.id, object_id=child.id, relation="acquired", observer_id=observer.id,
        evidence_id=ev.id, quote="acquired the child", event_date=None, event_date_precision="unknown",
    )
    w.relations.append(rel.id)
    with pytest.raises(cd.CandidateConflict, match="confirmed"):
        cd.accept(w.db, candidate_id=c.id, engagement_id=eng.id, user=admin)

    # A person confirms it → accepted, and the target lands in the parent's
    # engagement, attributed to the CHILD entity.
    entity_graph.decide(w.db, relation_id=rel.id, status="confirmed", user=admin)
    result = cd.accept(w.db, candidate_id=c.id, engagement_id=eng.id, user=admin)
    w.targets.append(result.target.id)
    assert (result.target.engagement_id, result.target.entity_id) == (eng.id, child.id)


def test_accept_refuses_abandoned_and_subjectless_engagements(w):
    subject = w.entity()
    c = w.filing_candidate(subject)
    admin = w.user()
    abandoned = w.engagement("abandoned", subject=subject)
    with pytest.raises(cd.CandidateConflict, match="abandoned"):
        cd.accept(w.db, candidate_id=c.id, engagement_id=abandoned.id, user=admin)
    no_subject = w.engagement("pre_close")
    with pytest.raises(cd.CandidateConflict):
        cd.accept(w.db, candidate_id=c.id, engagement_id=no_subject.id, user=admin)
    with pytest.raises(cd.CandidateInvalid):
        cd.accept(w.db, candidate_id=c.id, engagement_id=uuid.uuid4(), user=admin)


# ── 9. the domain is already a target (C4) ─────────────────────────────────


def test_existing_owned_target_is_a_conflict_and_is_left_unchanged(w):
    subject = w.entity()
    eng = w.engagement("pre_close", subject=subject)
    c = w.filing_candidate(subject)
    owned = Target(id=uuid.uuid4(), type=TargetType.DOMAIN.value, value=c.domain)
    w.db.add(owned)
    w.db.commit()
    w.targets.append(owned.id)

    with pytest.raises(cd.CandidateConflict, match="outside this engagement"):
        cd.accept(w.db, candidate_id=c.id, engagement_id=eng.id, user=w.user())
    w.db.refresh(owned)
    w.db.refresh(c)
    assert (owned.engagement_id, owned.entity_id, c.status) == (None, None, "proposed")


def test_existing_target_in_the_same_engagement_is_idempotent(w):
    subject = w.entity()
    eng = w.engagement("pre_close", subject=subject)
    c = w.filing_candidate(subject)
    same = Target(id=uuid.uuid4(), type=TargetType.DOMAIN.value, value=c.domain, engagement_id=eng.id)
    w.db.add(same)
    w.db.commit()
    w.targets.append(same.id)

    result = cd.accept(w.db, candidate_id=c.id, engagement_id=eng.id, user=w.user())
    assert (result.created, result.target.id, result.target.entity_id) == (False, same.id, subject.id)
    assert w.db.query(Target).filter(Target.value == c.domain).count() == 1


# ── 10. reject records who (acceptance 4) ──────────────────────────────────


def test_reject_records_who_and_is_final(w):
    subject = w.entity()
    eng = w.engagement("pre_close", subject=subject)
    c = w.filing_candidate(subject)
    admin = w.user()
    rejected = cd.reject(w.db, candidate_id=c.id, user=admin)
    assert (rejected.status, rejected.decided_by_id) == ("rejected", admin.id)
    assert rejected.decided_at is not None
    with pytest.raises(cd.CandidateConflict):
        cd.reject(w.db, candidate_id=c.id, user=admin)
    with pytest.raises(cd.CandidateConflict):
        cd.accept(w.db, candidate_id=c.id, engagement_id=eng.id, user=admin)


def test_deleting_the_accepted_target_does_not_break_the_row(w):
    """`target_id` is ON DELETE SET NULL, performed by Postgres as an UPDATE
    the guard trigger also sees — it must allow it."""
    subject = w.entity()
    eng = w.engagement("pre_close", subject=subject)
    c = w.filing_candidate(subject)
    result = cd.accept(w.db, candidate_id=c.id, engagement_id=eng.id, user=w.user())
    target_id = result.target.id
    w.db.query(Target).filter(Target.id == target_id).delete(synchronize_session=False)
    w.db.commit()
    w.db.refresh(c)
    assert (c.status, c.target_id, c.engagement_id) == ("accepted", None, eng.id)
