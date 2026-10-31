"""Org-discovery verifier runner and its triggers (planning#277 S1b part B).

The runner opens its own `SessionLocal()` (the test database), so every
fixture row is committed and removed by `World.close()`. Facts come from a
fake that counts calls; nothing here touches DNS or WHOIS. Synthetic data only.

Run with:  scripts/test.sh app/tests/test_org_discovery_runner.py
"""

import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import select, text

from app.api import entities as entities_api
from app.core.database import SessionLocal
from app.models.scope_candidate import ScopeCandidate, ScopeSignal
from app.models.user import UserRole
from app.services import edgar_html, edgar_ingest
from app.services.org_discovery import candidates as cd
from app.services.org_discovery import generators, runner, verifiers
from app.services.org_discovery.domain_facts import DomainFacts
from app.tests._entity_graph import make_observer
from app.tests._org_world import World, client, hexid
from app.tests.test_org_discovery_schema import _insert_candidate, _insert_signal


@pytest.fixture
def w():
    world = World()
    try:
        yield world
    finally:
        world.close()


class FakeFacts:
    """Every domain shares one vanity NS (a host under `ns_under`, which a test passes as a claimed
    domain of the root so the rule counts it) unless listed in `apart`; counts calls per domain."""

    def __init__(self, ns_under="fabrikam.com", apart=(), explode_on=()):
        self.shared_ns = (f"ns1.{ns_under}",)
        self.apart, self.explode_on = set(apart), set(explode_on)
        self.calls: list[str] = []

    def __call__(self, db, domain):
        self.calls.append(domain)
        if domain in self.explode_on:
            raise RuntimeError("lookup exploded")
        ns = ("ns9.contoso-dns.com",) if domain in self.apart else self.shared_ns
        return DomainFacts(
            domain=domain, ns=ns, mx=(), spf_senders=(), spf_includes=(), registrant_org=None,
            registrant_org_folded=None, lookup_errors=(),
        )


def _dom(tag="") -> str:
    return f"org277-{tag}{hexid()}.example.net"


def _claimed(w, root, value=None):
    c = w.candidate(root, value=value or _dom("a"))
    result = cd.claim(w.db, candidate_id=c.id, user=w.user())
    w.track_target(result.target.value)
    w.db.commit()
    return c


def _verifier_signals(candidate_id):
    db = SessionLocal()
    try:
        return list(db.execute(
            select(ScopeSignal).where(
                ScopeSignal.candidate_id == candidate_id, ScopeSignal.signal_type == "shared_vanity_ns"
            )
        ).scalars())
    finally:
        db.close()


# ── verify_new_candidates ───────────────────────────────────────────────────


def test_a_new_candidate_is_checked_against_every_claimed_domain_in_its_root_only(w, monkeypatch):
    root, other_root = w.ours(), w.ours()
    a1, a2 = _claimed(w, root), _claimed(w, root)
    foreign = _claimed(w, other_root)  # present, claimed, same facts: it must still not be an anchor
    open_c = w.candidate(root, value=_dom("c"))
    other_open = w.candidate(other_root, value=_dom("o"))
    fake = FakeFacts(a1.value)
    monkeypatch.setattr(runner, "_collect", fake)
    assert w.db.get(ScopeCandidate, foreign.id).status == "claimed"

    report = runner.verify_new_candidates([open_c.id])

    anchors = {s.anchor_candidate_id for s in _verifier_signals(open_c.id)}
    assert anchors == {a1.id, a2.id}
    assert foreign.value not in fake.calls and other_open.value not in fake.calls
    assert (report.pairs_checked, report.signals_recorded, report.signals_resighted, report.pairs_failed) == (2, 2, 0, 0)
    # idempotent: a second run re-sights the same two signals
    again = runner.verify_new_candidates([open_c.id])
    assert (again.signals_recorded, again.signals_resighted) == (0, 2)
    assert len(_verifier_signals(open_c.id)) == 2


def test_a_candidate_that_is_not_open_or_is_gone_is_skipped_and_counted(w, monkeypatch):
    root = w.ours()
    _claimed(w, root)
    rejected = w.candidate(root, value=_dom("r"))
    cd.reject(w.db, candidate_id=rejected.id, user=w.user(), reason="a vendor")
    fake = FakeFacts()
    monkeypatch.setattr(runner, "_collect", fake)
    report = runner.verify_new_candidates([rejected.id, uuid.uuid4()])
    assert (report.candidates_skipped, report.pairs_checked) == (2, 0)
    assert fake.calls == []


# ── verify_after_claim ──────────────────────────────────────────────────────


def test_a_claim_checks_every_open_candidate_in_the_root_and_never_selects_the_rest(w, monkeypatch):
    root = w.ours()
    anchor = _claimed(w, root)
    other_claimed = _claimed(w, root)
    o1, o2 = w.candidate(root, value=_dom("x")), w.candidate(root, value=_dom("y"))
    rejected = w.candidate(root, value=_dom("r"))
    cd.reject(w.db, candidate_id=rejected.id, user=w.user(), reason="a vendor")
    fake = FakeFacts(anchor.value)
    monkeypatch.setattr(runner, "_collect", fake)

    report = runner.verify_after_claim(anchor.id)

    for oc in (o1, o2):
        assert {s.anchor_candidate_id for s in _verifier_signals(oc.id)} == {anchor.id}
    assert _verifier_signals(rejected.id) == [] and _verifier_signals(other_claimed.id) == []
    # rejected / claimed rows are never selected (so not "skipped"), and never looked up
    assert rejected.value not in fake.calls and other_claimed.value not in fake.calls
    assert (report.pairs_checked, report.signals_recorded, report.candidates_skipped) == (2, 2, 0)


def test_after_claim_on_a_candidate_that_is_not_claimed_does_nothing(w, monkeypatch):
    root = w.ours()
    still_open = w.candidate(root, value=_dom("c"))
    fake = FakeFacts()
    monkeypatch.setattr(runner, "_collect", fake)
    report = runner.verify_after_claim(still_open.id)
    assert (report.candidates_skipped, report.pairs_checked, fake.calls) == (1, 0, [])
    assert runner.verify_after_claim(uuid.uuid4()).candidates_skipped == 1


# ── the facts cache ─────────────────────────────────────────────────────────


def test_each_domain_is_collected_once_per_run(w, monkeypatch):
    root = w.ours()
    anchor = _claimed(w, root)
    opens = [w.candidate(root, value=_dom(f"c{i}")) for i in range(3)]
    fake = FakeFacts()
    monkeypatch.setattr(runner, "_collect", fake)
    runner.verify_after_claim(anchor.id)
    assert sorted(fake.calls) == sorted([anchor.value, *[c.value for c in opens]])

    a2 = _claimed(w, root)
    fake.calls.clear()
    runner.verify_new_candidates([opens[0].id, opens[1].id])  # 2 candidates x 2 anchors (+ the earlier one)
    assert len(fake.calls) == len(set(fake.calls))
    assert set(fake.calls) == {opens[0].value, opens[1].value, anchor.value, a2.value}


# ── failure isolation ───────────────────────────────────────────────────────


def test_a_pair_that_breaks_the_session_does_not_stop_the_rest(w, monkeypatch):
    root = w.ours()
    anchor = _claimed(w, root)
    opens = sorted((w.candidate(root, value=_dom(f"c{i}")) for i in range(3)), key=lambda c: c.id)
    bad = opens[0]
    real = verifiers.verify_pair

    def flaky(db, *, candidate, **kw):
        if candidate.id == bad.id:
            db.execute(text("SELECT 1/0"))  # a real DB error: the session is now failed until rolled back
        return real(db, candidate=candidate, **kw)

    monkeypatch.setattr(runner, "_collect", FakeFacts(anchor.value))
    monkeypatch.setattr(runner.verifiers, "verify_pair", flaky)
    report = runner.verify_after_claim(anchor.id)

    assert report.pairs_failed == 1 and report.pairs_checked == 3
    assert report.signals_recorded == 2  # both others committed, no PendingRollbackError
    assert _verifier_signals(bad.id) == []
    assert all(len(_verifier_signals(c.id)) == 1 for c in opens[1:])


def test_a_lookup_that_raises_fails_only_its_own_pair(w, monkeypatch):
    root = w.ours()
    anchor = _claimed(w, root)
    good, broken = w.candidate(root, value=_dom("g")), w.candidate(root, value=_dom("b"))
    monkeypatch.setattr(runner, "_collect", FakeFacts(anchor.value, explode_on={broken.value}))
    report = runner.verify_after_claim(anchor.id)
    assert (report.pairs_failed, report.signals_recorded) == (1, 1)
    assert len(_verifier_signals(good.id)) == 1 and _verifier_signals(broken.id) == []


def test_the_result_is_committed_not_just_flushed(w, monkeypatch):
    root = w.ours()
    anchor = _claimed(w, root)
    c = w.candidate(root, value=_dom("c"))
    monkeypatch.setattr(runner, "_collect", FakeFacts(anchor.value))
    runner.verify_after_claim(anchor.id)
    fresh = SessionLocal()  # a different connection: only committed rows are visible
    try:
        n = fresh.execute(
            select(ScopeSignal).where(ScopeSignal.candidate_id == c.id, ScopeSignal.anchor_candidate_id == anchor.id)
        ).scalars().all()
        assert [s.matched_values for s in n] == [[f"ns1.{anchor.value}"]]
    finally:
        fresh.close()


def test_an_authorised_dmarc_report_address_commits_a_dmarc_signal(w, monkeypatch):
    root = w.ours()
    anchor = _claimed(w, root)
    c = w.candidate(root, value=_dom("c"))
    addr = f"dmarc@{anchor.value}"

    def collect(db, domain):
        mine = domain == c.value
        return DomainFacts(
            domain=domain, ns=(), mx=(), spf_senders=(), spf_includes=(), registrant_org=None,
            registrant_org_folded=None, lookup_errors=(),
            dmarc_record_name=f"_dmarc.{domain}" if mine else None,
            dmarc_rua=(addr,) if mine else (), dmarc_report_auth=((anchor.value, "authorised"),) if mine else (),
        )

    monkeypatch.setattr(runner, "_collect", collect)
    runner.verify_new_candidates([c.id])
    fresh = SessionLocal()
    try:
        rows = fresh.execute(
            select(ScopeSignal).where(
                ScopeSignal.candidate_id == c.id, ScopeSignal.signal_type == "dmarc_report_to_claimed"
            )
        ).scalars().all()
        assert [(s.anchor_candidate_id, s.matched_values) for s in rows] == [(anchor.id, [addr])]
    finally:
        fresh.close()


# ── triggers: routes ────────────────────────────────────────────────────────


def _spy(monkeypatch):
    calls = {"after_claim": [], "new": []}
    monkeypatch.setattr(runner, "verify_after_claim", lambda *a: calls["after_claim"].append(a))
    monkeypatch.setattr(runner, "verify_new_candidates", lambda *a: calls["new"].append(a))
    return calls


def test_claiming_schedules_the_verifier_for_that_candidate_and_a_failed_claim_does_not(w, monkeypatch):
    calls = _spy(monkeypatch)
    root = w.ours()
    c = w.candidate(root, value=_dom("c"))
    lead = _insert_candidate(w.db, root.id, value=_dom("l"))
    _insert_signal(w.db, lead, root.id, signal_type="research_quote", evidence_id=w.evidence_row().id, quote="q")
    headers = w.headers()

    r = client.post(f"/api/organizations/candidates/{lead}/claim", json={}, headers=headers)
    assert r.status_code == 409
    assert calls["after_claim"] == []  # the negative path, with the positive path below proving the spy works

    r = client.post(f"/api/organizations/candidates/{c.id}/claim", json={}, headers=headers)
    assert r.status_code == 200, r.text
    w.track_target(c.value)
    assert calls["after_claim"] == [(c.id,)]
    assert calls["new"] == []


def test_adding_an_organization_schedules_the_verifier_for_the_seed(w, monkeypatch):
    calls = _spy(monkeypatch)
    name, seed = f"Example Holdings {hexid()}", _dom("s")
    w.entity_names.append(name)
    w.track_target(seed)
    r = client.post(
        "/api/organizations/",
        json={"seed_domain": seed, "org_name": name, "relationship": "ours", "reference": "board approval 277"},
        headers=w.headers(),
    )
    assert r.status_code == 201, r.text
    w.entities.append(uuid.UUID(r.json()["organization_id"]))
    assert calls["after_claim"] == [(uuid.UUID(r.json()["candidate_id"]),)]
    seed_row = w.db.get(ScopeCandidate, uuid.UUID(r.json()["candidate_id"]))
    assert seed_row.value == seed and seed_row.status == "claimed"


def test_adding_a_candidate_by_person_schedules_only_when_it_is_new(w, monkeypatch):
    calls = _spy(monkeypatch)
    root = w.ours()
    d = _dom("p")
    body = {
        "domain": d, "source_url": "https://news.example.test/deal",
        "excerpt": f"The business operates www.{d} today.", "quote": f"operates www.{d} today",
    }
    url = f"/api/organizations/{root.id}/candidates"
    headers = w.headers()
    r = client.post(url, json=body, headers=headers)
    assert r.status_code == 201, r.text
    cid = uuid.UUID(r.json()["id"])
    w.evidence.extend(s.evidence_id for s in w.db.query(ScopeSignal).filter_by(candidate_id=cid))
    assert calls["new"] == [([cid],)]
    r2 = client.post(url, json=body, headers=headers)  # the same domain again: a re-sighting
    assert r2.status_code == 201, r2.text
    assert calls["new"] == [([cid],)]
    assert calls["after_claim"] == []


# ── triggers: EDGAR ─────────────────────────────────────────────────────────


def test_the_filer_website_generator_collects_only_newly_created_candidates(w, monkeypatch):
    root = w.ours()
    filer = w.child_of(root)
    filer.cik = "0000000077"
    w.db.commit()
    observer = make_observer(w.db)
    w.observers.append(observer.id)
    evidence = w.evidence_row()
    known, fresh = _dom("k"), _dom("f")
    w.candidate(root, value=known)  # already a candidate: a re-sighting
    monkeypatch.setattr(
        edgar_html, "find_website_mentions",
        lambda lines: [(known, f"website {known}"), (fresh, f"website {fresh}")],
    )
    collected: list = []
    kw = dict(filer=filer, observer=observer, evidence_id=evidence.id, lines=["x"], filing_date=None)
    recorded, existing, _ = generators.record_filer_websites(w.db, created_candidate_ids=collected, **kw)
    w.db.commit()
    assert (recorded, existing) == (2, 0)  # the known candidate got a NEW signal, but is not a new candidate
    fresh_id = w.db.execute(select(ScopeCandidate.id).where(
        ScopeCandidate.root_entity_id == root.id, ScopeCandidate.value == fresh)).scalar_one()
    assert collected == [fresh_id]

    again: list = []
    recorded, existing, _ = generators.record_filer_websites(w.db, created_candidate_ids=again, **kw)
    w.db.commit()
    assert (recorded, existing) == (0, 2) and again == []
    # the collector is optional: the 3-tuple contract is unchanged
    assert generators.record_filer_websites(w.db, **kw) == (0, 2, 0)


def test_a_verifier_failure_after_an_ingest_does_not_fail_it(monkeypatch):
    marks: list[dict] = []
    ids = [uuid.uuid4()]
    monkeypatch.setattr(
        entities_api.edgar_ingest, "ingest_cik",
        lambda db, cik: edgar_ingest.IngestResult(entity_id=None, created_candidate_ids=list(ids)),
    )
    monkeypatch.setattr(entities_api, "_mark_run", lambda run_id, **f: marks.append(f))
    seen: list = []

    def boom(candidate_ids):
        seen.append(candidate_ids)
        raise RuntimeError("verifier down")

    monkeypatch.setattr(runner, "verify_new_candidates", boom)
    entities_api._run_edgar_ingest(uuid.uuid4(), "0000000077")  # must not raise
    assert seen == [ids]  # the verifier WAS reached
    assert [m["status"] for m in marks] == ["running", "succeeded"]  # and the run still succeeded
    assert "created_candidate_ids" not in marks[1]["result"]  # UUIDs never reach the JSON run result

    seen.clear()
    monkeypatch.setattr(
        entities_api.edgar_ingest, "ingest_cik", lambda db, cik: edgar_ingest.IngestResult(entity_id=None)
    )
    entities_api._run_edgar_ingest(uuid.uuid4(), "0000000077")
    assert seen == []  # nothing created, nothing verified


# ── API: matched_values ─────────────────────────────────────────────────────


def test_candidate_detail_returns_matched_values_for_a_verifier_signal_and_null_otherwise(w, monkeypatch):
    root = w.ours()
    anchor = _claimed(w, root)
    c = w.candidate(root, value=_dom("c"))
    cd.record_signal(w.db, root_entity_id=root.id, value=c.value, signal_type="admin_seed",
                     anchor_kind="person", via_entity_id=root.id)
    w.db.commit()
    f = FakeFacts(anchor.value)
    outcomes = verifiers.verify_pair(
        w.db, candidate=w.db.get(ScopeCandidate, c.id), anchor=w.db.get(ScopeCandidate, anchor.id),
        candidate_facts=f(w.db, c.value), anchor_facts=f(w.db, anchor.value),
    )
    w.db.commit()
    assert len(outcomes) == 1
    r = client.get(f"/api/organizations/candidates/{c.id}", headers=w.headers(role=UserRole.VIEWER.value))
    assert r.status_code == 200, r.text
    by_type = {s["signal_type"]: s for s in r.json()["signal_details"]}
    assert by_type["shared_vanity_ns"]["matched_values"] == [f"ns1.{anchor.value}"]
    assert by_type["admin_seed"]["matched_values"] is None
    assert by_type["person_evidence"]["matched_values"] is None
