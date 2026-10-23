"""First-run seeding from a company name (planning#232).

`app.services.onboarding` and its two ADMIN routes in `app.api.entities`
(`GET /onboarding/registrant-search`, `POST /onboarding/seed`). SEC is never
contacted: every request goes through the `_Sec` MockTransport shared with
`test_registrant_link.py`, and every company and CIK is invented
(`make_cik`'s 99-prefixed CIKs cannot belong to a real filer). The EDGAR
ingest and the AI read are stubbed where a test needs the background chain
to run (TestClient runs BackgroundTasks inline); their own suites cover what
they do.

Run with:  scripts/test.ps1 app/tests/test_onboarding.py
"""

import uuid
from datetime import date, datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.core.auth import create_access_token
from app.core.config import settings
from app.main import app
from app.models.audit import AuditLog
from app.models.engagement import Engagement
from app.models.entity_ingest_run import EntityIngestRun
from app.models.observer import Observer
from app.models.org_entity import OrgEntity
from app.models.scope_candidate import ScopeCandidate
from app.models.target import Target
from app.models.user import UserRole
from app.services import (
    acquisition_reader, edgar_ingest, entity_relationship, llm_connector, onboarding,
)
from app.services.org_discovery import generators
from app.services import registrant_link as rl
from app.tests.test_registrant_link import (  # noqa: F401  (`sec` is a fixture)
    _World, sec, search_list_html, submissions_json,
)

client = TestClient(app)

SEARCH = "/api/entities/onboarding/registrant-search"
SEED = "/api/entities/onboarding/seed"


@pytest.fixture
def w():
    world = _World()
    engagements: list[uuid.UUID] = []
    world.engagements = engagements
    yield world
    world.db.rollback()
    # Entities the seed created are found by CIK, not tracked by the test.
    if world.ciks:
        world.entities.extend(
            r[0] for r in world.db.query(OrgEntity.id).filter(OrgEntity.cik.in_(world.ciks)).all()
        )
    if engagements:
        world.db.query(Engagement).filter(Engagement.id.in_(engagements)).delete(synchronize_session=False)
        world.db.commit()
    world.close()


def _stub_ingest(monkeypatch, calls=None, *, section=False, w=None, propose=None):
    def fake_ingest(db, c):
        if calls is not None:
            calls.append(("ingest", c))
        entity = db.query(OrgEntity).filter(OrgEntity.cik == c).one()
        if section:
            w.section(entity)
        if propose:
            propose(db, entity)
        return edgar_ingest.IngestResult(entity_id=entity.id, denied=[])

    monkeypatch.setattr(edgar_ingest, "ingest_cik", fake_ingest)


def _entity_by_cik(w, cik):
    w.db.expire_all()
    return w.db.query(OrgEntity).filter(OrgEntity.cik == cik).one_or_none()


def _runs(w, cik, kind="edgar_ingest"):
    w.db.expire_all()
    return w.db.query(EntityIngestRun).filter_by(cik=cik, kind=kind).all()


def _audit_changes(w):
    rows = w.db.query(AuditLog).filter(AuditLog.user_id.in_(w.users)).all()
    return [a.detail["changes"] for a in rows if "reference" in ((a.detail or {}).get("changes") or {})]


# ── 1. search ───────────────────────────────────────────────────────────────


def test_search_gives_an_admin_hints_and_flags_a_taken_cik(w, sec):
    free, taken, gone = w.cik(), w.cik(), w.cik()
    holder = w.entity(cik=taken)
    sec.search_pages = [search_list_html([free, taken, gone])]
    sec.submissions = {free: submissions_json(free), taken: submissions_json(taken, name="OTHER CO")}
    r = client.get(SEARCH, params={"q": "Example"}, headers=w.headers())
    assert r.status_code == 200, r.text
    out = r.json()
    assert [c["cik"] for c in out] == [free, taken]  # the CIK SEC no longer serves is dropped
    assert (out[0]["name"], out[0]["first_filing"], out[0]["last_filing"]) == (
        "EXAMPLE TARGET CORP", "1999-01-04", "2012-03-01")
    assert out[0]["taken_by_id"] is None
    assert out[1]["taken_by_id"] == str(holder.id)
    # The path was reached: one search, then a submissions fetch per candidate.
    assert sum(q.url.path == "/cgi-bin/browse-edgar" for q in sec.requests) == 1
    assert sum(q.url.path.startswith("/submissions/") for q in sec.requests) == 3


@pytest.mark.parametrize("role", [UserRole.INTEGRATION_ADMIN.value, UserRole.VIEWER.value])
def test_search_is_admin_only_and_contacts_sec_for_nobody_else(w, sec, role):
    sec.search_pages = [search_list_html([w.cik()])]
    r = client.get(SEARCH, params={"q": "Example"}, headers=w.headers(role))
    assert r.status_code == 403
    assert sec.requests == []


@pytest.mark.parametrize("q", ["", "   ", "x" * 201])
def test_search_refuses_an_empty_or_overlong_query_before_contacting_sec(w, sec, q):
    sec.search_pages = [search_list_html([w.cik()])]
    r = client.get(SEARCH, params={"q": q}, headers=w.headers())
    assert r.status_code == 422
    assert sec.requests == []


def test_search_caps_the_candidates_at_ten(w, sec):
    ciks = [w.cik() for _ in range(12)]
    sec.search_pages = [search_list_html(ciks)]
    sec.submissions = {c: submissions_json(c) for c in ciks}
    r = client.get(SEARCH, params={"q": "Example"}, headers=w.headers())
    assert r.status_code == 200, r.text
    assert len(r.json()) == rl.MAX_CANDIDATES == 10
    assert sum(q.url.path.startswith("/submissions/") for q in sec.requests) == 10


def test_search_needs_no_entity_while_the_old_route_stays_gated(w, sec):
    cik = w.cik()
    sec.search_pages = [search_list_html([cik])]
    sec.submissions = {cik: submissions_json(cik)}
    assert w.db.query(OrgEntity).filter(OrgEntity.cik == cik).count() == 0
    r = client.get(SEARCH, params={"q": "Example"}, headers=w.headers())
    assert r.status_code == 200 and [c["cik"] for c in r.json()] == [cik]
    assert len(sec.requests) >= 2  # reached SEC

    # Unchanged: the registrant-link route still refuses a CIK-less company
    # with no confirmed acquisition, and sends nothing.
    lonely = w.entity()
    before = len(sec.requests)
    r = client.get(f"/api/entities/{lonely.id}/registrant-candidates", params={"q": "Example"}, headers=w.headers())
    assert r.status_code == 409
    assert len(sec.requests) == before


# ── 3-9. seed ───────────────────────────────────────────────────────────────


def test_seed_a_new_cik_creates_the_entity_marks_it_ours_and_runs_the_ingest(w, sec, monkeypatch):
    cik = w.cik()
    sec.submissions = {cik: submissions_json(cik, name="EXAMPLE HOLDINGS A")}
    calls: list[tuple] = []
    _stub_ingest(monkeypatch, calls)
    admin = w.user()
    h = {"Authorization": f"Bearer {create_access_token(str(admin.id), admin.role)}"}

    r = client.post(SEED, json={"cik": cik}, headers=h)
    assert r.status_code == 202, r.text
    body = r.json()
    assert (body["cik"], body["entity_name"], body["ours_set_now"], body["relationship_previous"], body["ingest"]) == (
        cik, "EXAMPLE HOLDINGS A", True, None, "queued")
    assert any(q.url.path.startswith("/submissions/") for q in sec.requests)

    e = _entity_by_cik(w, cik)
    assert str(e.id) == body["entity_id"] and e.legal_name == "EXAMPLE HOLDINGS A"
    assert e.relationship == "ours" and e.ours_reference == "first-run onboarding"
    assert e.ours_authorised_by_id == admin.id and e.ours_authorised_at is not None

    assert calls == [("ingest", cik)]  # the background task ran
    (run,) = _runs(w, cik)
    assert str(run.id) == body["run_id"] and run.status == "succeeded" and run.requested_by_id == admin.id

    (changes,) = _audit_changes(w)
    assert changes["cik"] == cik and changes["reference"] == "first-run onboarding"
    assert changes["relationship"] == {"from": None, "to": "ours"}


def test_seed_reuses_an_existing_entity_with_no_relationship(w, sec, monkeypatch):
    cik = w.cik()
    existing = w.entity(cik=cik, name="Example Holdings B")
    sec.submissions = {cik: submissions_json(cik, name="SOMETHING ELSE")}
    _stub_ingest(monkeypatch)
    r = client.post(SEED, json={"cik": cik}, headers=w.headers())
    assert r.status_code == 202, r.text
    assert r.json()["entity_id"] == str(existing.id) and r.json()["ours_set_now"] is True
    w.db.expire_all()
    assert w.db.query(OrgEntity).filter(OrgEntity.cik == cik).count() == 1
    e = w.db.get(OrgEntity, existing.id)
    assert e.relationship == "ours" and e.legal_name == "Example Holdings B"  # never renamed
    assert len(_runs(w, cik)) == 1


def test_seed_an_already_ours_entity_keeps_its_original_authorisation(w, sec, monkeypatch):
    cik = w.cik()
    e = w.entity(cik=cik)
    first = w.user()
    entity_relationship.set_ours(w.db, entity_id=e.id, reference="original reference", user=first)
    w.db.expire_all()
    stamp = w.db.get(OrgEntity, e.id).ours_authorised_at
    _stub_ingest(monkeypatch)
    r = client.post(SEED, json={"cik": cik}, headers=w.headers())
    assert r.status_code == 202, r.text
    assert r.json()["ours_set_now"] is False and r.json()["relationship_previous"] == "ours"
    w.db.expire_all()
    e = w.db.get(OrgEntity, e.id)
    assert (e.ours_authorised_by_id, e.ours_reference, e.ours_authorised_at) == (first.id, "original reference", stamp)
    assert len(_runs(w, cik)) == 1  # the ingest was still queued
    (changes,) = _audit_changes(w)
    assert changes["ours_set_now"] is False


def test_seed_refuses_an_engagement_subject_and_queues_nothing(w, sec):
    cik = w.cik()
    e = w.entity(cik=cik)
    _e, _prev, engagement, _created = entity_relationship.set_ma_target(
        w.db, entity_id=e.id, user=w.user(), new_engagement_name=f"Example Engagement {uuid.uuid4().hex[:8]}",
        may_clear_ours=True,
    )
    w.engagements.append(engagement.id)
    r = client.post(SEED, json={"cik": cik}, headers=w.headers())
    assert r.status_code == 409, r.text
    assert "engagement" in r.json()["detail"]
    w.db.expire_all()
    assert w.db.get(OrgEntity, e.id).relationship == "ma_target"
    assert _runs(w, cik) == []


def test_seed_an_unknown_cik_is_404_and_creates_nothing(w, sec):
    cik = w.cik()
    sec.submissions = {}
    r = client.post(SEED, json={"cik": cik}, headers=w.headers())
    assert r.status_code == 404, r.text
    assert any(q.url.path == f"/submissions/CIK{cik}.json" for q in sec.requests)  # SEC was asked
    assert _entity_by_cik(w, cik) is None
    assert _runs(w, cik) == []


def test_seed_a_registrant_with_no_name_is_422_and_creates_nothing(w, sec):
    cik = w.cik()
    sec.submissions = {cik: submissions_json(cik, name="")}
    r = client.post(SEED, json={"cik": cik}, headers=w.headers())
    assert r.status_code == 422, r.text
    assert any(q.url.path == f"/submissions/CIK{cik}.json" for q in sec.requests)  # SEC was asked
    assert _entity_by_cik(w, cik) is None
    assert _runs(w, cik) == []


def test_seed_with_an_ingest_already_active_is_not_an_error(w, sec):
    cik = w.cik()
    sec.submissions = {cik: submissions_json(cik)}
    w.db.add(EntityIngestRun(cik=cik, kind="edgar_ingest", status="running", started_at=datetime.now(timezone.utc)))
    w.db.commit()
    r = client.post(SEED, json={"cik": cik}, headers=w.headers())
    assert r.status_code == 202, r.text
    assert r.json()["ingest"] == "already_running" and r.json()["run_id"] is None
    assert r.json()["ours_set_now"] is True
    assert _entity_by_cik(w, cik).relationship == "ours"
    (run,) = _runs(w, cik)
    assert run.status == "running"  # the one that was already there, untouched


def test_seed_rejects_a_bad_cik(w, sec):
    r = client.post(SEED, json={"cik": "12ab"}, headers=w.headers())
    assert r.status_code == 422 and sec.requests == []


def test_seed_without_a_sec_user_agent_is_409(w, sec, monkeypatch):
    monkeypatch.setattr(settings, "sec_user_agent", "")
    cik = w.cik()
    r = client.post(SEED, json={"cik": cik}, headers=w.headers())
    assert r.status_code == 409, r.text
    assert sec.requests == [] and _entity_by_cik(w, cik) is None


@pytest.mark.parametrize("role", [UserRole.INTEGRATION_ADMIN.value, UserRole.VIEWER.value])
def test_seed_is_admin_only(w, sec, role):
    cik = w.cik()
    existing = w.entity(cik=cik)
    sec.submissions = {cik: submissions_json(cik)}
    r = client.post(SEED, json={"cik": cik}, headers=w.headers(role))
    assert r.status_code == 403
    assert sec.requests == []
    w.db.expire_all()
    assert w.db.get(OrgEntity, existing.id).relationship is None
    assert _runs(w, cik) == []

    other = w.cik()
    assert client.post(SEED, json={"cik": other}, headers=w.headers(role)).status_code == 403
    assert _entity_by_cik(w, other) is None


# ── 10. the acceptance line: nothing seeded enters scope ────────────────────


def test_nothing_seeded_enters_scope(w, sec, monkeypatch):
    """The ingest records the filer's website as a signal on an open candidate
    (the real `record_filer_websites`, called from the stubbed ingest: the
    10-K document fetch is the ingest suite's concern). Seeding must leave it
    open, add no Target, and an INTEGRATION_ADMIN cannot claim it."""
    cik = w.cik()
    sec.submissions = {cik: submissions_json(cik, name="EXAMPLE HOLDINGS C")}
    observer = w.db.query(Observer).filter(Observer.name == "edgar_10k_website").one()
    proposed: list[bool] = []

    def propose(db, entity):
        recorded, _existing, _unanchored = generators.record_filer_websites(
            db, filer=entity, observer=observer, evidence_id=w.ev().id,
            lines=["Our website is www.fabrikam.com"], filing_date=date(2012, 3, 1),
        )
        db.commit()
        proposed.append(recorded == 1)

    _stub_ingest(monkeypatch, propose=propose)
    targets_before = w.db.query(Target).count()

    r = client.post(SEED, json={"cik": cik}, headers=w.headers())
    assert r.status_code == 202, r.text
    assert proposed == [True]  # the precondition: a signal really was recorded

    w.db.expire_all()
    entity = _entity_by_cik(w, cik)
    assert entity.relationship == "ours"
    cands = w.db.query(ScopeCandidate).filter(ScopeCandidate.root_entity_id == entity.id).all()
    assert [c.value for c in cands] == ["fabrikam.com"]
    assert all(c.status == "open" for c in cands)
    assert w.db.query(Target).count() == targets_before

    r = client.post(
        f"/api/organizations/candidates/{cands[0].id}/claim", json={},
        headers=w.headers(UserRole.INTEGRATION_ADMIN.value),
    )
    assert r.status_code == 403
    w.db.expire_all()
    assert w.db.get(ScopeCandidate, cands[0].id).status == "open"
    assert w.db.query(Target).count() == targets_before


# ── 11. the follow-up read ──────────────────────────────────────────────────


def test_followup_records_why_the_read_did_not_run(w, sec, monkeypatch):
    cik = w.cik()
    sec.submissions = {cik: submissions_json(cik)}
    read_called: list = []
    _stub_ingest(monkeypatch, section=True, w=w)
    monkeypatch.setattr(llm_connector, "is_configured", lambda db: False)
    monkeypatch.setattr(acquisition_reader, "read_acquisitions", lambda *a, **k: read_called.append(1))
    r = client.post(SEED, json={"cik": cik}, headers=w.headers())
    assert r.status_code == 202, r.text
    (run,) = _runs(w, cik)
    assert run.status == "succeeded"  # the chain was reached
    assert run.result["acquisition_read"]["status"] == "skipped"
    assert "OpenRouter" in run.result["acquisition_read"]["reason"]
    assert read_called == [] and _runs(w, cik, "acquisition_read") == []


def test_followup_queues_and_runs_the_read_when_configured(w, sec, monkeypatch):
    cik = w.cik()
    sec.submissions = {cik: submissions_json(cik)}
    reads: list = []

    def fake_read(db, *, entity_id, run_id):
        reads.append(entity_id)
        return SimpleNamespace(as_dict=lambda: {"proposed": 0})

    _stub_ingest(monkeypatch, section=True, w=w)
    monkeypatch.setattr(acquisition_reader, "read_acquisitions", fake_read)
    monkeypatch.setattr(llm_connector, "is_configured", lambda db: True)
    monkeypatch.setattr(llm_connector, "models_configured", lambda db: True)
    r = client.post(SEED, json={"cik": cik}, headers=w.headers())
    assert r.status_code == 202, r.text
    entity = _entity_by_cik(w, cik)
    assert reads == [entity.id]  # CALLED, with the seeded entity
    (ingest_run,) = _runs(w, cik)
    (read_run,) = _runs(w, cik, "acquisition_read")
    assert read_run.status == "succeeded"
    assert ingest_run.result["acquisition_read"] == {"status": "queued", "run_id": str(read_run.id)}


def test_followup_skips_once_the_company_is_no_longer_ours(w, sec, monkeypatch):
    monkeypatch.setattr(llm_connector, "is_configured", lambda db: True)
    monkeypatch.setattr(llm_connector, "models_configured", lambda db: True)
    cik = w.cik()
    e = w.entity(cik=cik)
    w.section(e)
    entity_relationship.set_ours(w.db, entity_id=e.id, reference="x", user=w.user())

    run, reason = onboarding.followup_read(w.db, entity_id=e.id, cik10=cik, user_id=None)
    assert reason is None and (run.kind, run.cik, run.status) == ("acquisition_read", cik, "queued")
    w.db.delete(run)
    w.db.commit()

    entity_relationship.clear(w.db, entity_id=e.id, may_clear_ours=True)
    run, reason = onboarding.followup_read(w.db, entity_id=e.id, cik10=cik, user_id=None)
    assert run is None and reason == "the company is no longer marked as ours"
    assert _runs(w, cik, "acquisition_read") == []

    run, reason = onboarding.followup_read(w.db, entity_id=e.id, cik10=w.cik(), user_id=None)
    assert run is None and "removed or changed" in reason
