"""Coverage for app.services.edgar_ingest (planning#213, L4 slice 1) — the
CIK-to-rows pipeline: `formerNames` -> `formerly_named` relations,
qualifying 8-K/8-K/A items -> `entity_filing_events`, posture gating, and
the re-ingest idempotency/non-regression properties.

Recorded fixtures only, served through `httpx.MockTransport` on
`sec_edgar._transport`. No live SEC call, no real company name or CIK —
every CIK is drawn by `app.tests._edgar.make_cik` (synthetic, "99"-prefixed,
collision-checked against `org_entities`), every name is invented
("Example Holdings ..."). Direct-seeding/cleanup-by-id style, matching
`_entity_graph.py`/`_engagement.py`'s convention.

Run with:  backend/scripts/test.ps1 app/tests/test_edgar_ingest.py
       or: pytest app/tests/test_edgar_ingest.py
"""

import json
import uuid
from datetime import date

import httpx
import pytest
from sqlalchemy import select

from app.core.config import settings
from app.core.database import SessionLocal
from app.models.engagement import EngagementPosture
from app.models.entity_filing_event import EntityFilingEvent
from app.models.entity_relation import EntityRelation
from app.models.observer import Observer
from app.models.org_entity import OrgEntity
from app.models.user import User, UserRole
from app.services import edgar_ingest, entity_graph, posture, sec_edgar
from app.tests._edgar import cleanup_cik, make_cik
from app.tests._engagement import cleanup_engagement, make_engagement
from app.tests._entity_graph import cleanup_observer, make_observer

_UA = "planning213-tests contact@example.invalid"


# ── fixture builders ─────────────────────────────────────────────────────────

def _empty_recent() -> dict:
    return {"form": [], "accessionNumber": [], "filingDate": [], "items": []}


def _recent(forms, accessions, filing_dates, items) -> dict:
    return {"form": forms, "accessionNumber": accessions, "filingDate": filing_dates, "items": items}


def _submissions(cik: str, *, name="Example Holdings A", former_names=None, recent=None, files=None, nonce=None) -> dict:
    payload = {
        "cik": cik,
        "name": name,
        "formerNames": former_names if former_names is not None else [],
        "filings": {
            "recent": recent if recent is not None else _empty_recent(),
            "files": files if files is not None else [],
        },
    }
    if nonce is not None:
        payload["_test_nonce"] = nonce
    return payload


def _accession(seq: int) -> str:
    return f"9900000{seq:03d}-24-{seq:06d}"


class _RoutedTransport:
    """Serves the main submissions body plus any number of paged bodies,
    routed by the request path (`.../CIK...json` vs `.../CIK...-submissions-
    NNN.json`). Records every request received."""

    def __init__(self, *, main_body: dict, pages: dict[str, dict] | None = None):
        self.main_body = json.dumps(main_body).encode()
        self.pages = {name: json.dumps(body).encode() for name, body in (pages or {}).items()}
        self.requests: list[httpx.Request] = []

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        leaf = path.rsplit("/", 1)[-1]
        if leaf in self.pages:
            return httpx.Response(200, content=self.pages[leaf])
        return httpx.Response(200, content=self.main_body)

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)


@pytest.fixture(autouse=True)
def _set_user_agent(monkeypatch):
    monkeypatch.setattr(settings, "sec_user_agent", _UA)


def _observer_by_name(db, name: str) -> Observer:
    return db.execute(select(Observer).where(Observer.name == name)).scalar_one()


def _relations_for(db, entity_id) -> list[EntityRelation]:
    return db.execute(select(EntityRelation).where(EntityRelation.subject_id == entity_id)).scalars().all()


def _events_for(db, entity_id) -> list[EntityFilingEvent]:
    return db.execute(select(EntityFilingEvent).where(EntityFilingEvent.entity_id == entity_id)).scalars().all()


def _run_ingest(db, cik: str, main_body: dict, pages: dict[str, dict] | None = None):
    transport = _RoutedTransport(main_body=main_body, pages=pages)
    sec_edgar._transport = transport.transport
    sec_edgar._sleep = lambda _s: None
    try:
        result = edgar_ingest.ingest_cik(db, cik)
    finally:
        sec_edgar._transport = None
        sec_edgar._sleep = __import__("time").sleep
    return result, transport


# ── 8-K item filtering ───────────────────────────────────────────────────────

def test_events_created_for_matching_8k_and_not_for_others():
    db = SessionLocal()
    cik = make_cik(db)
    try:
        recent = _recent(
            forms=["8-K", "8-K/A", "8-K", "10-K"],
            accessions=[_accession(1), _accession(2), _accession(3), _accession(4)],
            filing_dates=["2024-01-02", "2024-02-03", "2024-03-04", "2024-04-05"],
            items=["2.01,9.01", "5.01", "1.01,9.01", "2.01"],
        )
        result, transport = _run_ingest(db, cik, _submissions(cik, recent=recent))

        assert result.events_inserted == 2
        assert result.malformed_skipped == 0

        entity = db.execute(select(OrgEntity).where(OrgEntity.cik == cik)).scalar_one()
        events = {e.accession_number: e for e in _events_for(db, entity.id)}
        assert set(events) == {_accession(1), _accession(2)}
        assert events[_accession(1)].items == "2.01,9.01"
        assert events[_accession(1)].filing_date == date(2024, 1, 2)
        assert events[_accession(2)].form == "8-K/A"
        assert events[_accession(2)].items == "5.01"
    finally:
        cleanup_cik(db, cik)
        db.close()


def test_paged_filing_event_carries_the_pages_own_evidence():
    db = SessionLocal()
    cik = make_cik(db)
    try:
        page_name = f"CIK{cik}-submissions-001.json"
        page_recent = _recent(
            forms=["8-K"], accessions=[_accession(10)], filing_dates=["2019-05-01"], items=["2.01"],
        )
        main = _submissions(cik, files=[{"name": page_name}])
        result, transport = _run_ingest(db, cik, main, pages={page_name: page_recent})

        assert result.pages_fetched == 1
        assert result.events_inserted == 1

        entity = db.execute(select(OrgEntity).where(OrgEntity.cik == cik)).scalar_one()
        events = _events_for(db, entity.id)
        assert len(events) == 1
        event = events[0]

        # Its evidence_id must be the PAGE's fetch, not the main submissions
        # JSON's fetch.
        main_url = f"https://data.sec.gov/submissions/CIK{cik}.json"
        page_url = f"https://data.sec.gov/submissions/{page_name}"
        main_fetch_id = db.execute(
            select(entity_graph.EvidenceFetch.id).where(entity_graph.EvidenceFetch.source_url == main_url)
        ).scalar_one()
        page_fetch_id = db.execute(
            select(entity_graph.EvidenceFetch.id).where(entity_graph.EvidenceFetch.source_url == page_url)
        ).scalar_one()
        assert event.evidence_id == page_fetch_id
        assert event.evidence_id != main_fetch_id
    finally:
        cleanup_cik(db, cik)
        db.close()


def test_malformed_accession_is_skipped_and_counted_not_raised():
    db = SessionLocal()
    cik = make_cik(db)
    try:
        recent = _recent(
            forms=["8-K"], accessions=["not-a-valid-accession"], filing_dates=["2024-01-02"], items=["2.01"],
        )
        result, _ = _run_ingest(db, cik, _submissions(cik, recent=recent))

        assert result.malformed_skipped == 1
        assert result.events_inserted == 0

        entity = db.execute(select(OrgEntity).where(OrgEntity.cik == cik)).scalar_one()
        assert _events_for(db, entity.id) == []
    finally:
        cleanup_cik(db, cik)
        db.close()


# ── formerNames -> formerly_named relations ─────────────────────────────────

def test_former_name_relation_is_confirmed_source_decided_with_canonical_quote():
    db = SessionLocal()
    cik = make_cik(db)
    try:
        entry = {"name": "Example Predecessor Corp", "from": "2010-01-01", "to": "2015-06-30"}
        result, _ = _run_ingest(db, cik, _submissions(cik, former_names=[entry]))

        assert result.former_names_asserted == 1
        assert result.former_names_skipped == 0

        entity = db.execute(select(OrgEntity).where(OrgEntity.cik == cik)).scalar_one()
        observer = _observer_by_name(db, edgar_ingest.OBSERVER_FORMER_NAMES)
        rows = _relations_for(db, entity.id)
        assert len(rows) == 1
        row = rows[0]

        assert row.status == "confirmed"
        assert row.decision_kind == "source"
        assert row.observer_confirms is True
        assert row.observer_id == observer.id
        assert row.event_date == date(2015, 6, 30)
        assert row.event_date_precision == "day"
        assert row.quote == json.dumps(entry, sort_keys=True, separators=(",", ":"))

        former_entity = db.get(OrgEntity, row.object_id)
        assert former_entity.legal_name == "Example Predecessor Corp"
        assert former_entity.cik is None
    finally:
        cleanup_cik(db, cik)
        db.close()


def test_former_name_equal_to_current_name_is_skipped():
    db = SessionLocal()
    cik = make_cik(db)
    try:
        result, _ = _run_ingest(
            db, cik, _submissions(cik, name="Example Holdings A", former_names=[{"name": "Example Holdings A", "to": "2020-01-01"}])
        )
        assert result.former_names_asserted == 0
        assert result.former_names_skipped == 1

        entity = db.execute(select(OrgEntity).where(OrgEntity.cik == cik)).scalar_one()
        assert _relations_for(db, entity.id) == []
    finally:
        cleanup_cik(db, cik)
        db.close()


def test_no_cross_cik_reuse_of_a_shared_former_name():
    db = SessionLocal()
    cik_a = make_cik(db)
    cik_b = make_cik(db)
    try:
        shared_entry = {"name": "Shared Former Name Co", "to": "2018-01-01"}
        result_a, _ = _run_ingest(db, cik_a, _submissions(cik_a, name="Example Holdings A", former_names=[shared_entry]))
        result_b, _ = _run_ingest(db, cik_b, _submissions(cik_b, name="Example Holdings B", former_names=[shared_entry]))

        assert result_a.former_names_asserted == 1
        assert result_b.former_names_asserted == 1

        entity_a = db.execute(select(OrgEntity).where(OrgEntity.cik == cik_a)).scalar_one()
        entity_b = db.execute(select(OrgEntity).where(OrgEntity.cik == cik_b)).scalar_one()
        object_a = _relations_for(db, entity_a.id)[0].object_id
        object_b = _relations_for(db, entity_b.id)[0].object_id

        assert object_a != object_b
        assert db.get(OrgEntity, object_a).legal_name == "Shared Former Name Co"
        assert db.get(OrgEntity, object_b).legal_name == "Shared Former Name Co"
    finally:
        cleanup_cik(db, cik_a)
        cleanup_cik(db, cik_b)
        db.close()


# ── entity upsert ────────────────────────────────────────────────────────────

def test_existing_entitys_legal_name_is_never_overwritten():
    db = SessionLocal()
    cik = make_cik(db)
    entity_id = None
    try:
        entity = OrgEntity(id=uuid.uuid4(), legal_name="Original Filed Name", cik=cik)
        db.add(entity)
        db.commit()
        entity_id = entity.id

        _run_ingest(db, cik, _submissions(cik, name="A Completely Different SEC Name"))

        db.expire_all()
        refreshed = db.get(OrgEntity, entity_id)
        assert refreshed.legal_name == "Original Filed Name"
    finally:
        cleanup_cik(db, cik)
        db.close()


# ── re-ingest idempotency and non-regression ────────────────────────────────

def test_reingesting_identical_bytes_creates_zero_new_rows():
    db = SessionLocal()
    cik = make_cik(db)
    try:
        recent = _recent(forms=["8-K"], accessions=[_accession(20)], filing_dates=["2021-01-01"], items=["2.01"])
        body = _submissions(cik, former_names=[{"name": "Example Predecessor D", "to": "2019-01-01"}], recent=recent)

        result1, _ = _run_ingest(db, cik, body)
        assert result1.events_inserted == 1
        assert result1.former_names_asserted == 1

        entity = db.execute(select(OrgEntity).where(OrgEntity.cik == cik)).scalar_one()
        relations_before = len(_relations_for(db, entity.id))
        events_before = len(_events_for(db, entity.id))
        entities_before = db.query(OrgEntity).count()

        result2, _ = _run_ingest(db, cik, body)
        assert result2.events_inserted == 0
        assert result2.events_existing == 1

        assert len(_events_for(db, entity.id)) == events_before
    finally:
        cleanup_cik(db, cik)
        db.close()


def test_reingest_after_new_filing_adds_one_event_and_nothing_else():
    db = SessionLocal()
    cik = make_cik(db)
    try:
        former_name_entry = {"name": "Example Predecessor E", "to": "2017-01-01"}
        recent1 = _recent(forms=["8-K"], accessions=[_accession(30)], filing_dates=["2020-01-01"], items=["2.01"])
        body1 = _submissions(cik, former_names=[former_name_entry], recent=recent1)
        result1, _ = _run_ingest(db, cik, body1)
        assert result1.events_inserted == 1
        assert result1.former_names_asserted == 1

        # A new filing landed: the SAME accession as before, plus one new
        # one, and the SAME former name entry — this is what a real
        # re-ingest of a growing submissions JSON looks like.
        recent2 = _recent(
            forms=["8-K", "8-K"],
            accessions=[_accession(30), _accession(31)],
            filing_dates=["2020-01-01", "2022-03-03"],
            items=["2.01", "5.01"],
        )
        body2 = _submissions(cik, former_names=[former_name_entry], recent=recent2)
        result2, _ = _run_ingest(db, cik, body2)

        assert result2.events_inserted == 1
        assert result2.events_existing == 1

        entity = db.execute(select(OrgEntity).where(OrgEntity.cik == cik)).scalar_one()
        assert len(_events_for(db, entity.id)) == 2
        assert len(_relations_for(db, entity.id)) == 1
    finally:
        cleanup_cik(db, cik)
        db.close()


def test_person_rejected_relation_survives_reingest():
    db = SessionLocal()
    cik = make_cik(db)
    admin = User(
        id=uuid.uuid4(), email=f"edgar213-admin-{uuid.uuid4().hex[:8]}@example.invalid",
        full_name="edgar213 test admin", role=UserRole.ADMIN.value, is_active=True,
    )
    db.add(admin)
    db.commit()
    try:
        entry = {"name": "Example Predecessor F", "to": "2016-01-01"}
        body1 = _submissions(cik, former_names=[entry])
        result1, _ = _run_ingest(db, cik, body1)
        assert result1.former_names_asserted == 1

        entity = db.execute(select(OrgEntity).where(OrgEntity.cik == cik)).scalar_one()
        relation = _relations_for(db, entity.id)[0]
        object_id = relation.object_id

        entity_graph.decide(db, relation_id=relation.id, status="rejected", user=admin)
        db.expire_all()
        rejected = db.get(EntityRelation, relation.id)
        assert rejected.status == "rejected"

        relations_before = len(_relations_for(db, entity.id))
        entities_before = db.query(OrgEntity).count()

        # Change the fixture bytes (new evidence sha256) WITHOUT touching
        # the formerNames entry itself or adding any lineage-eligible
        # filing — an inert nonce is enough to force a fresh evidence row,
        # which is exactly the "a new filing landed" trigger this test
        # guards against.
        body2 = _submissions(cik, former_names=[entry], nonce=str(uuid.uuid4()))
        result2, _ = _run_ingest(db, cik, body2)

        assert result2.former_names_asserted == 0
        assert result2.former_names_skipped == 1
        assert len(_relations_for(db, entity.id)) == relations_before
        assert db.query(OrgEntity).count() == entities_before

        # Match the object by NAME, not by `object_id`: a re-assertion that
        # slipped past the skip would mint a NEW former-name entity, so an
        # id filter would never see the re-confirmed edge it exists to catch.
        edges = entity_graph.project_edges(db, entity_id=entity.id)
        confirmed_to_name = [
            e for e in edges
            if e["relation"] == "formerly_named"
            and e["confirmed"]
            and db.get(OrgEntity, e["object"]).legal_name == entry["name"]
        ]
        assert confirmed_to_name == []
        assert db.get(EntityRelation, relation.id).status == "rejected"
        assert object_id is not None
    finally:
        cleanup_cik(db, cik)
        db.query(User).filter(User.id == admin.id).delete(synchronize_session=False)
        db.commit()
        db.close()


# ── settings gate ────────────────────────────────────────────────────────────

def test_unset_user_agent_raises_and_makes_zero_requests(monkeypatch):
    monkeypatch.setattr(settings, "sec_user_agent", None)
    db = SessionLocal()
    cik = make_cik(db)
    scripted_seen: list[httpx.Request] = []

    def _handle(request: httpx.Request) -> httpx.Response:
        scripted_seen.append(request)
        return httpx.Response(200, content=json.dumps(_submissions(cik)).encode())

    sec_edgar._transport = httpx.MockTransport(_handle)
    try:
        with pytest.raises(edgar_ingest.EdgarNotConfigured):
            edgar_ingest.ingest_cik(db, cik)
    finally:
        sec_edgar._transport = None
        cleanup_cik(db, cik)
        db.close()

    assert scripted_seen == []


def test_invalid_user_agent_raises_and_makes_zero_requests(monkeypatch):
    monkeypatch.setattr(settings, "sec_user_agent", "no-at-sign-here")
    db = SessionLocal()
    cik = make_cik(db)
    scripted_seen: list[httpx.Request] = []

    def _handle(request: httpx.Request) -> httpx.Response:
        scripted_seen.append(request)
        return httpx.Response(200, content=json.dumps(_submissions(cik)).encode())

    sec_edgar._transport = httpx.MockTransport(_handle)
    try:
        with pytest.raises(edgar_ingest.EdgarNotConfigured):
            edgar_ingest.ingest_cik(db, cik)
    finally:
        sec_edgar._transport = None
        cleanup_cik(db, cik)
        db.close()

    assert scripted_seen == []


# ── posture path is live ─────────────────────────────────────────────────────

def test_posture_denies_8k_signal_but_not_former_names_when_restricting(monkeypatch):
    db = SessionLocal()
    cik = make_cik(db)
    entity_id = None
    engagement_id = None
    throwaway_observer_id = None
    try:
        entity = OrgEntity(id=uuid.uuid4(), legal_name="Example Restricted Holdings", cik=cik)
        db.add(entity)
        db.commit()
        entity_id = entity.id

        throwaway = make_observer(db, noise_class="target_host")
        throwaway_observer_id = throwaway.id

        engagement = make_engagement(db, posture=EngagementPosture.PRE_CLOSE.value, subject_entity_id=entity.id)
        engagement_id = engagement.id

        # Precondition check: the entity exists and the engagement actually
        # restricts — otherwise a "denied" assertion below could pass
        # vacuously because nothing was ever eligible to be denied.
        assert db.get(OrgEntity, entity_id) is not None
        assert posture.posture_restricts(engagement.posture) is True

        monkeypatch.setattr(edgar_ingest, "OBSERVER_8K_ITEMS", throwaway.name)

        entry = {"name": "Example Predecessor Restricted", "to": "2018-01-01"}
        recent = _recent(forms=["8-K"], accessions=[_accession(40)], filing_dates=["2020-01-01"], items=["2.01"])
        body = _submissions(cik, name="Example Restricted Holdings", former_names=[entry], recent=recent)
        result, _ = _run_ingest(db, cik, body)

        assert throwaway.name in result.denied
        assert result.events_inserted == 0
        assert result.former_names_asserted == 1
        assert len(_events_for(db, entity_id)) == 0
    finally:
        cleanup_engagement(db, engagement_id)
        cleanup_cik(db, cik)
        cleanup_observer(db, throwaway_observer_id)
        db.close()


def test_posture_control_events_are_written_without_a_restricting_engagement(monkeypatch):
    """Paired with the test above, same setup minus the engagement — proves
    the denial above is not vacuous (i.e. it is not simply that this
    fixture never produces events at all)."""
    db = SessionLocal()
    cik = make_cik(db)
    throwaway_observer_id = None
    try:
        throwaway = make_observer(db, noise_class="target_host")
        throwaway_observer_id = throwaway.id

        monkeypatch.setattr(edgar_ingest, "OBSERVER_8K_ITEMS", throwaway.name)

        recent = _recent(forms=["8-K"], accessions=[_accession(41)], filing_dates=["2020-01-01"], items=["2.01"])
        body = _submissions(cik, name="Example Unrestricted Holdings", recent=recent)
        result, _ = _run_ingest(db, cik, body)

        assert result.denied == []
        assert result.events_inserted == 1
    finally:
        cleanup_cik(db, cik)
        cleanup_observer(db, throwaway_observer_id)
        db.close()
