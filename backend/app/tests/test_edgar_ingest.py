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
from app.models.entity_filing_section import EntityFilingSection
from app.models.entity_relation import EntityRelation
from app.models.entity_subsidiary_listing import EntitySubsidiaryListing
from app.models.observer import Observer
from app.models.org_entity import OrgEntity
from app.models.user import User, UserRole
from app.services import edgar_ingest, entity_graph, posture, sec_edgar
from app.tests._edgar import cleanup_cik, ex21_paragraph_html, html_table, index_html, make_cik, text_block_html, tr
from app.tests._engagement import cleanup_engagement, make_engagement
from app.tests._entity_graph import cleanup_observer, make_observer

_UA = "planning213-tests contact@example.invalid"


# ── fixture builders ─────────────────────────────────────────────────────────

def _empty_recent() -> dict:
    return {"form": [], "accessionNumber": [], "filingDate": [], "items": []}


def _recent(forms, accessions, filing_dates, items, *, report_dates=None, primary_documents=None) -> dict:
    d = {"form": forms, "accessionNumber": accessions, "filingDate": filing_dates, "items": items}
    # Optional, real-submissions-JSON-shaped parallel arrays — only read by
    # slice 2's annual-report collection (`edgar_ingest._collect_annual_
    # reports`); `sec_edgar._validate_parallel_arrays` never looks at them,
    # so omitting them (as every slice-1 test still does) changes nothing.
    if report_dates is not None:
        d["reportDate"] = report_dates
    if primary_documents is not None:
        d["primaryDocument"] = primary_documents
    return d


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


def _relations_for_object(db, entity_id) -> list[EntityRelation]:
    """`subsidiary_of` relations have the FILER as `object_id` (subject is
    the subsidiary — see `EntityRelation`'s direction convention), so
    finding "every relation about this filer's subsidiaries" queries
    `object_id`, unlike `_relations_for` above (`formerly_named`, subject-
    side)."""
    return db.execute(select(EntityRelation).where(EntityRelation.object_id == entity_id)).scalars().all()


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


class _EdgarTransport:
    """Serves the main submissions body, any number of paged bodies, any
    number of filing-index pages (keyed by ACCESSION), and any number of
    filing documents (keyed by FILENAME) — the slice 2 superset of
    `_RoutedTransport`, routed by request PATH. Records every request
    received, so a test can assert exactly which document (by Type, never
    by filename) was actually fetched.

    `document_statuses`/`index_statuses` (planning#220) let a test script a
    non-200 response for a specific document filename / index accession —
    the SAME status on every request to that leaf, which is sufficient to
    exercise both a never-retried failure (403/404, one request) and an
    exhausted-retry failure (429/5xx, `sec_edgar._MAX_ATTEMPTS` requests —
    `sec_edgar._fetch`'s own retry loop calls this handler again each
    attempt) without this transport needing to track attempt counts
    itself."""

    def __init__(
        self,
        *,
        main_body: dict,
        pages: dict[str, dict] | None = None,
        indexes: dict[str, str] | None = None,
        documents: dict[str, str] | None = None,
        document_statuses: dict[str, int] | None = None,
        index_statuses: dict[str, int] | None = None,
    ):
        self.main_body = json.dumps(main_body).encode()
        self.pages = {name: json.dumps(body).encode() for name, body in (pages or {}).items()}
        self.indexes = {accession: body.encode() for accession, body in (indexes or {}).items()}
        self.documents = {filename: body.encode() for filename, body in (documents or {}).items()}
        self.document_statuses = dict(document_statuses or {})
        self.index_statuses = dict(index_statuses or {})
        self.requests: list[httpx.Request] = []

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        leaf = request.url.path.rsplit("/", 1)[-1]
        if leaf.endswith("-index.htm"):
            accession = leaf[: -len("-index.htm")]
            if accession in self.index_statuses:
                return httpx.Response(self.index_statuses[accession], content=b"scripted index error")
            body = self.indexes.get(accession)
            if body is None:
                return httpx.Response(404, content=b"index not found")
            return httpx.Response(200, content=body)
        if leaf in self.document_statuses:
            return httpx.Response(self.document_statuses[leaf], content=b"scripted document error")
        if leaf in self.documents:
            return httpx.Response(200, content=self.documents[leaf])
        if leaf in self.pages:
            return httpx.Response(200, content=self.pages[leaf])
        return httpx.Response(200, content=self.main_body)

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)


def _run_ingest2(
    db,
    cik: str,
    main_body: dict,
    *,
    pages: dict[str, dict] | None = None,
    indexes: dict[str, str] | None = None,
    documents: dict[str, str] | None = None,
    document_statuses: dict[str, int] | None = None,
    index_statuses: dict[str, int] | None = None,
):
    transport = _EdgarTransport(
        main_body=main_body,
        pages=pages,
        indexes=indexes,
        documents=documents,
        document_statuses=document_statuses,
        index_statuses=index_statuses,
    )
    sec_edgar._transport = transport.transport
    sec_edgar._sleep = lambda _s: None
    try:
        result = edgar_ingest.ingest_cik(db, cik)
    finally:
        sec_edgar._transport = None
        sec_edgar._sleep = __import__("time").sleep
    return result, transport


def _listings_for(db, filer_entity_id) -> list[EntitySubsidiaryListing]:
    return (
        db.execute(
            select(EntitySubsidiaryListing)
            .where(EntitySubsidiaryListing.filer_entity_id == filer_entity_id)
            .order_by(EntitySubsidiaryListing.filing_date, EntitySubsidiaryListing.row_index)
        )
        .scalars()
        .all()
    )


def _sections_for(db, entity_id) -> list[EntityFilingSection]:
    return db.execute(select(EntityFilingSection).where(EntityFilingSection.entity_id == entity_id)).scalars().all()


def _annual_report_recent(entries: list[dict]) -> dict:
    """Builds a `filings.recent`-shaped dict from a list of
    `{form, accession, filing_date, report_date=None, primary_document=None,
    items=""}` dicts — the slice 2 tests' terser way to specify one or more
    10-K/10-K405/10-K-A rows without repeating four/six parallel lists by
    hand."""
    return _recent(
        forms=[e["form"] for e in entries],
        accessions=[e["accession"] for e in entries],
        filing_dates=[e["filing_date"] for e in entries],
        items=[e.get("items", "") for e in entries],
        report_dates=[e.get("report_date") for e in entries] if any("report_date" in e for e in entries) else None,
        primary_documents=[e.get("primary_document") for e in entries]
        if any("primary_document" in e for e in entries)
        else None,
    )


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
        # The trailing "10-K" entry is here to prove a 10-K's own items are
        # never treated as an event (§4.8 of slice 1's spec) — but since
        # slice 2, ANY 10-K in `recent` also gets its index fetched (both
        # `edgar_ex21`/`edgar_10k_footnote` are permitted by default). An
        # empty index (no EX-21 row, no "10-K"-typed row) makes that
        # slice-2 side effect a harmless no-op (`ex21_missing`/
        # `sections_not_found` both increment) rather than 5 failed
        # retries against `_RoutedTransport`'s JSON fallback body.
        result, transport = _run_ingest2(
            db, cik, _submissions(cik, recent=recent), indexes={_accession(4): index_html([])}
        )

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


# ═════════════════════════════════════════════════════════════════════════
# planning#213 slice 2 — EX-21 subsidiary listings + Business Combinations
# footnote. Fixtures route through `_EdgarTransport` (indexes keyed by
# accession, documents keyed by filename); `_no_bc_document()` is a benign
# primary-10-K body with no Business Combinations heading, used wherever a
# test only cares about the EX-21 signal, so the footnote signal's
# independent run stays harmless and deterministic rather than falling
# through to the transport's JSON fallback body.
# ═════════════════════════════════════════════════════════════════════════


def _no_bc_document() -> str:
    return text_block_html(["Item 1. Business.", "Nothing relevant to Business Combinations here."])


# ── EX-21 locate-by-Type ─────────────────────────────────────────────────────

def test_ex21_located_by_index_type_not_by_filename():
    db = SessionLocal()
    cik = make_cik(db)
    try:
        accession = _accession(100)
        recent = _annual_report_recent([{"form": "10-K", "accession": accession, "filing_date": "2024-03-01"}])
        idx = index_html([
            {"Seq": "1", "Description": "10-K", "Document": "form10k.htm", "Type": "10-K", "Size": "4000000"},
            # A file literally NAMED ex21.htm, but typed as the certification
            # exhibit — must NOT be fetched for the EX-21 signal.
            {"Seq": "2", "Description": "Certification", "Document": "ex21.htm", "Type": "EX-32.1", "Size": "500"},
            {"Seq": "3", "Description": "Subsidiaries", "Document": "exhibit99.htm", "Type": "EX-21.1", "Size": "12000"},
        ])
        ex21_body = html_table(tr("Name", "Jurisdiction"), tr("Example Sub Alpha LLC", "Delaware"))
        body = _submissions(cik, recent=recent)
        result, transport = _run_ingest2(
            db, cik, body,
            indexes={accession: idx},
            documents={"exhibit99.htm": ex21_body, "ex21.htm": "MUST NEVER BE FETCHED", "form10k.htm": _no_bc_document()},
        )

        requested_leaves = {req.url.path.rsplit("/", 1)[-1] for req in transport.requests}
        assert "exhibit99.htm" in requested_leaves
        assert "ex21.htm" not in requested_leaves

        assert result.ex21_docs == 1
        assert result.subsidiary_rows == 1
        assert result.subsidiaries_proposed == 1

        entity = db.execute(select(OrgEntity).where(OrgEntity.cik == cik)).scalar_one()
        listings = _listings_for(db, entity.id)
        assert len(listings) == 1
        assert listings[0].name == "Example Sub Alpha LLC"
        assert listings[0].jurisdiction == "Delaware"
        assert listings[0].exhibit_type == "EX-21.1"
    finally:
        cleanup_cik(db, cik)
        db.close()


def test_every_ex21_exhibit_in_a_filing_is_processed():
    # An EX-21.1 and an EX-21.2 can list DIFFERENT subsidiaries; processing
    # only the first would silently drop the second's.
    db = SessionLocal()
    cik = make_cik(db)
    try:
        accession = _accession(102)
        recent = _annual_report_recent([{"form": "10-K", "accession": accession, "filing_date": "2024-03-01"}])
        idx = index_html([
            {"Seq": "1", "Description": "10-K", "Document": "form10k.htm", "Type": "10-K", "Size": "4000000"},
            {"Seq": "2", "Description": "Subsidiaries", "Document": "subs-a.htm", "Type": "EX-21.1", "Size": "9000"},
            {"Seq": "3", "Description": "Subsidiaries", "Document": "subs-b.htm", "Type": "EX-21.2", "Size": "9000"},
        ])
        body = _submissions(cik, recent=recent)
        result, transport = _run_ingest2(
            db, cik, body,
            indexes={accession: idx},
            documents={
                "subs-a.htm": html_table(tr("Name", "Jurisdiction"), tr("Example Sub North LLC", "Delaware")),
                "subs-b.htm": html_table(tr("Name", "Jurisdiction"), tr("Example Sub South LLC", "Nevada")),
                "form10k.htm": _no_bc_document(),
            },
        )

        requested_leaves = {req.url.path.rsplit("/", 1)[-1] for req in transport.requests}
        assert {"subs-a.htm", "subs-b.htm"} <= requested_leaves
        assert result.ex21_docs == 2
        assert result.subsidiaries_proposed == 2
        entity = db.execute(select(OrgEntity).where(OrgEntity.cik == cik)).scalar_one()
        by_name = {l.name: l.exhibit_type for l in _listings_for(db, entity.id)}
        assert by_name == {"Example Sub North LLC": "EX-21.1", "Example Sub South LLC": "EX-21.2"}
    finally:
        cleanup_cik(db, cik)
        db.close()


def test_an_invalid_ex21_filename_is_skipped_and_the_valid_one_still_processed():
    db = SessionLocal()
    cik = make_cik(db)
    try:
        accession = _accession(103)
        recent = _annual_report_recent([{"form": "10-K", "accession": accession, "filing_date": "2024-03-01"}])
        idx = index_html([
            {"Seq": "1", "Description": "10-K", "Document": "form10k.htm", "Type": "10-K", "Size": "4000000"},
            {"Seq": "2", "Description": "Subsidiaries", "Document": "../escape.htm", "Type": "EX-21.1", "Size": "9000"},
            {"Seq": "3", "Description": "Subsidiaries", "Document": "subs-ok.htm", "Type": "EX-21.2", "Size": "9000"},
        ])
        body = _submissions(cik, recent=recent)
        result, transport = _run_ingest2(
            db, cik, body,
            indexes={accession: idx},
            documents={
                "subs-ok.htm": html_table(tr("Name", "Jurisdiction"), tr("Example Sub Valid LLC", "Delaware")),
                "form10k.htm": _no_bc_document(),
            },
        )

        requested_leaves = [req.url.path.rsplit("/", 1)[-1] for req in transport.requests]
        assert "escape.htm" not in requested_leaves
        assert not any(".." in req.url.path for req in transport.requests)
        assert result.invalid_filename_skipped == 1
        assert result.ex21_docs == 1
        assert result.subsidiaries_proposed == 1
    finally:
        cleanup_cik(db, cik)
        db.close()


def test_no_ex21_in_index_counts_ex21_missing_without_error():
    db = SessionLocal()
    cik = make_cik(db)
    try:
        accession = _accession(101)
        recent = _annual_report_recent([{"form": "10-K", "accession": accession, "filing_date": "2024-03-01"}])
        idx = index_html([{"Seq": "1", "Description": "10-K", "Document": "form10k.htm", "Type": "10-K", "Size": "4000000"}])
        body = _submissions(cik, recent=recent)
        result, _ = _run_ingest2(db, cik, body, indexes={accession: idx}, documents={"form10k.htm": _no_bc_document()})

        assert result.ex21_missing == 1
        assert result.ex21_docs == 0
        entity = db.execute(select(OrgEntity).where(OrgEntity.cik == cik)).scalar_one()
        assert _listings_for(db, entity.id) == []
    finally:
        cleanup_cik(db, cik)
        db.close()


def test_ex21_table_with_heading_header_filer_row_and_entities_produces_three_listings_and_proposals():
    db = SessionLocal()
    cik = make_cik(db)
    try:
        accession = _accession(102)
        recent = _annual_report_recent([{"form": "10-K", "accession": accession, "filing_date": "2024-03-01"}])
        idx = index_html([
            {"Document": "form10k.htm", "Type": "10-K"},
            {"Document": "subs.htm", "Type": "EX-21.1"},
        ])
        ex21_body = html_table(
            tr("Subsidiaries of the Registrant:"),
            tr("Name", "Jurisdiction"),
            tr("Example Holdings A", "Delaware"),  # equals the filer's own current name — skipped
            tr("Example Sub One LLC", "Delaware"),
            tr("Example Sub &amp; Two LLC", "New&nbsp;York"),
            tr("Example Sub Three Inc", "Nevada"),
        )
        body = _submissions(cik, name="Example Holdings A", recent=recent)
        result, _ = _run_ingest2(
            db, cik, body, indexes={accession: idx},
            documents={"subs.htm": ex21_body, "form10k.htm": _no_bc_document()},
        )

        assert result.subsidiary_rows == 3
        assert result.subsidiaries_proposed == 3
        assert result.subsidiaries_skipped == 0
        # The label row, the Name/Jurisdiction header row, and the
        # filer's-own-name row.
        assert result.ex21_heading_rows_skipped == 3

        entity = db.execute(select(OrgEntity).where(OrgEntity.cik == cik)).scalar_one()
        listings = _listings_for(db, entity.id)
        assert len(listings) == 3
        by_name = {r.name: r for r in listings}
        assert set(by_name) == {"Example Sub One LLC", "Example Sub & Two LLC", "Example Sub Three Inc"}
        assert by_name["Example Sub & Two LLC"].jurisdiction == "New York"
        assert by_name["Example Sub & Two LLC"].cells == ["Example Sub & Two LLC", "New York"]

        proposed = [r for r in _relations_for_object(db, entity.id) if r.relation == "subsidiary_of"]
        assert len(proposed) == 3
        assert all(r.status == "proposed" for r in proposed)
        assert all(r.observer_confirms is False for r in proposed)
    finally:
        cleanup_cik(db, cik)
        db.close()


# ── snapshot + reuse across years ────────────────────────────────────────────

def test_two_years_reuse_entities_and_propose_only_the_new_subsidiary():
    db = SessionLocal()
    cik = make_cik(db)
    try:
        acc_y1, acc_y2 = _accession(110), _accession(111)
        idx_y1 = index_html([{"Document": "subs1.htm", "Type": "EX-21.1"}, {"Document": "form1.htm", "Type": "10-K"}])
        idx_y2 = index_html([{"Document": "subs2.htm", "Type": "EX-21.1"}, {"Document": "form2.htm", "Type": "10-K"}])
        ex21_y1 = html_table(tr("Name", "Jurisdiction"), tr("Example Sub A", "Delaware"), tr("Example Sub B", "Nevada"))
        ex21_y2 = html_table(
            tr("Name", "Jurisdiction"),
            tr("Example Sub A", "Delaware"),
            tr("Example Sub B", "Nevada"),
            tr("Example Sub C", "Texas"),
        )
        # Fixture lists the NEWER 10-K first in `recent` — processing order
        # must still be oldest-first (required by the spec).
        recent = _annual_report_recent([
            {"form": "10-K", "accession": acc_y2, "filing_date": "2024-03-01"},
            {"form": "10-K", "accession": acc_y1, "filing_date": "2023-03-01"},
        ])
        body = _submissions(cik, recent=recent)
        result, _ = _run_ingest2(
            db, cik, body,
            indexes={acc_y1: idx_y1, acc_y2: idx_y2},
            documents={
                "subs1.htm": ex21_y1, "form1.htm": _no_bc_document(),
                "subs2.htm": ex21_y2, "form2.htm": _no_bc_document(),
            },
        )

        assert result.subsidiary_rows == 5
        assert result.subsidiaries_proposed == 3
        assert result.subsidiaries_skipped == 2

        entity = db.execute(select(OrgEntity).where(OrgEntity.cik == cik)).scalar_one()
        listings = _listings_for(db, entity.id)
        by_accession: dict[str, list] = {}
        for row in listings:
            by_accession.setdefault(row.accession_number, []).append(row)
        assert len(by_accession[acc_y1]) == 2
        assert len(by_accession[acc_y2]) == 3

        a_ids = {row.subsidiary_entity_id for row in listings if row.name == "Example Sub A"}
        b_ids = {row.subsidiary_entity_id for row in listings if row.name == "Example Sub B"}
        assert len(a_ids) == 1
        assert len(b_ids) == 1

        # "First appearance" (§4) means the proposal cites YEAR 1's EX-21 as
        # evidence, not year 2's — the aggregate counts above are the same
        # either way processing is ordered (reuse only cares whether A/B
        # PRE-EXIST, not which calendar year that pre-existing row is from),
        # so this is the assertion that actually catches mutation M6
        # (newest-first processing): a newest-first run would propose A/B
        # off year 2's evidence and skip year 1's re-processing instead.
        a_entity_id = next(iter(a_ids))
        a_relation = db.execute(
            select(EntityRelation).where(
                EntityRelation.subject_id == a_entity_id, EntityRelation.relation == "subsidiary_of"
            )
        ).scalar_one()
        year1_evidence_id = db.execute(
            select(entity_graph.EvidenceFetch.id).where(entity_graph.EvidenceFetch.source_url.contains("subs1.htm"))
        ).scalar_one()
        year2_evidence_id = db.execute(
            select(entity_graph.EvidenceFetch.id).where(entity_graph.EvidenceFetch.source_url.contains("subs2.htm"))
        ).scalar_one()
        assert a_relation.evidence_id == year1_evidence_id
        assert a_relation.evidence_id != year2_evidence_id
    finally:
        cleanup_cik(db, cik)
        db.close()


def test_same_name_different_jurisdiction_are_two_distinct_entities():
    db = SessionLocal()
    cik = make_cik(db)
    try:
        acc_y1, acc_y2 = _accession(120), _accession(121)
        idx_y1 = index_html([{"Document": "subsY1.htm", "Type": "EX-21.1"}, {"Document": "f1.htm", "Type": "10-K"}])
        idx_y2 = index_html([{"Document": "subsY2.htm", "Type": "EX-21.1"}, {"Document": "f2.htm", "Type": "10-K"}])
        ex21_y1 = html_table(tr("Name", "Jurisdiction"), tr("Example Ambiguous Sub LLC", "Delaware"))
        ex21_y2 = html_table(tr("Name", "Jurisdiction"), tr("Example Ambiguous Sub LLC", "Nevada"))
        recent = _annual_report_recent([
            {"form": "10-K", "accession": acc_y1, "filing_date": "2023-03-01"},
            {"form": "10-K", "accession": acc_y2, "filing_date": "2024-03-01"},
        ])
        body = _submissions(cik, recent=recent)
        result, _ = _run_ingest2(
            db, cik, body,
            indexes={acc_y1: idx_y1, acc_y2: idx_y2},
            documents={
                "subsY1.htm": ex21_y1, "f1.htm": _no_bc_document(),
                "subsY2.htm": ex21_y2, "f2.htm": _no_bc_document(),
            },
        )

        assert result.subsidiaries_proposed == 2
        assert result.subsidiaries_skipped == 0

        entity = db.execute(select(OrgEntity).where(OrgEntity.cik == cik)).scalar_one()
        listings = _listings_for(db, entity.id)
        assert len({row.subsidiary_entity_id for row in listings}) == 2
    finally:
        cleanup_cik(db, cik)
        db.close()


def test_ex21_rejected_proposal_survives_reingest_of_a_later_year():
    db = SessionLocal()
    cik = make_cik(db)
    admin = User(
        id=uuid.uuid4(), email=f"edgar213b-admin-{uuid.uuid4().hex[:8]}@example.invalid",
        full_name="edgar213 slice2 test admin", role=UserRole.ADMIN.value, is_active=True,
    )
    db.add(admin)
    db.commit()
    try:
        acc_y1, acc_y2 = _accession(130), _accession(131)
        idx_y1 = index_html([{"Document": "s1.htm", "Type": "EX-21.1"}, {"Document": "f1.htm", "Type": "10-K"}])
        idx_y2 = index_html([{"Document": "s2.htm", "Type": "EX-21.1"}, {"Document": "f2.htm", "Type": "10-K"}])
        ex21_y1 = html_table(tr("Name", "Jurisdiction"), tr("Example Rejected Sub LLC", "Delaware"))
        ex21_y2 = html_table(tr("Name", "Jurisdiction"), tr("Example Rejected Sub LLC", "Delaware"))

        recent1 = _annual_report_recent([{"form": "10-K", "accession": acc_y1, "filing_date": "2023-03-01"}])
        body1 = _submissions(cik, recent=recent1)
        result1, _ = _run_ingest2(
            db, cik, body1, indexes={acc_y1: idx_y1}, documents={"s1.htm": ex21_y1, "f1.htm": _no_bc_document()},
        )
        assert result1.subsidiaries_proposed == 1

        entity = db.execute(select(OrgEntity).where(OrgEntity.cik == cik)).scalar_one()
        relation = _relations_for_object(db, entity.id)[0]
        entity_graph.decide(db, relation_id=relation.id, status="rejected", user=admin)
        db.expire_all()
        assert db.get(EntityRelation, relation.id).status == "rejected"

        relations_before = len(_relations_for_object(db, entity.id))
        entities_before = db.query(OrgEntity).count()

        recent2 = _annual_report_recent([
            {"form": "10-K", "accession": acc_y1, "filing_date": "2023-03-01"},
            {"form": "10-K", "accession": acc_y2, "filing_date": "2024-03-01"},
        ])
        body2 = _submissions(cik, recent=recent2)
        result2, _ = _run_ingest2(
            db, cik, body2,
            indexes={acc_y1: idx_y1, acc_y2: idx_y2},
            documents={
                "s1.htm": ex21_y1, "f1.htm": _no_bc_document(),
                "s2.htm": ex21_y2, "f2.htm": _no_bc_document(),
            },
        )

        # A listing row IS added for year 2; NO new relation (a mutant that
        # dropped the reuse rule, or matched by id instead of name, would
        # tick `subsidiaries_proposed` here). `subsidiaries_skipped` is 2,
        # not 1: `recent2` still lists year 1's accession too (the same
        # "old entry stays, new one is added" shape slice 1's own re-ingest
        # test uses) — its already-stored row is re-processed (no new
        # listing row, ON CONFLICT DO NOTHING) and hits the same
        # status-blind relation skip a second time, alongside year 2's.
        assert result2.subsidiaries_proposed == 0
        assert result2.subsidiaries_skipped == 2
        assert db.query(OrgEntity).count() == entities_before
        assert len(_relations_for_object(db, entity.id)) == relations_before

        listings = _listings_for(db, entity.id)
        assert len(listings) == 2
        assert len({row.subsidiary_entity_id for row in listings}) == 1

        # Match by NAME, not id: a mutant that mints a NEW entity instead of
        # reusing the rejected one's would slip a fresh, non-rejected edge
        # past an id-based filter.
        edges = entity_graph.project_edges(db, entity_id=entity.id)
        matching = [
            e for e in edges
            if e["relation"] == "subsidiary_of"
            and db.get(OrgEntity, e["subject"]).legal_name == "Example Rejected Sub LLC"
        ]
        assert matching == []
    finally:
        cleanup_cik(db, cik)
        db.query(User).filter(User.id == admin.id).delete(synchronize_session=False)
        db.commit()
        db.close()


def test_no_cross_filer_reuse_of_a_shared_subsidiary_name_and_jurisdiction():
    db = SessionLocal()
    cik_a = make_cik(db)
    cik_b = make_cik(db)
    try:
        acc_a, acc_b = _accession(140), _accession(141)
        idx_a = index_html([{"Document": "sa.htm", "Type": "EX-21.1"}, {"Document": "fa.htm", "Type": "10-K"}])
        idx_b = index_html([{"Document": "sb.htm", "Type": "EX-21.1"}, {"Document": "fb.htm", "Type": "10-K"}])
        shared_row = html_table(tr("Name", "Jurisdiction"), tr("Example Shared Sub LLC", "Delaware"))

        recent_a = _annual_report_recent([{"form": "10-K", "accession": acc_a, "filing_date": "2024-01-01"}])
        recent_b = _annual_report_recent([{"form": "10-K", "accession": acc_b, "filing_date": "2024-01-01"}])
        body_a = _submissions(cik_a, name="Example Holdings A", recent=recent_a)
        body_b = _submissions(cik_b, name="Example Holdings B", recent=recent_b)

        result_a, _ = _run_ingest2(
            db, cik_a, body_a, indexes={acc_a: idx_a}, documents={"sa.htm": shared_row, "fa.htm": _no_bc_document()},
        )
        result_b, _ = _run_ingest2(
            db, cik_b, body_b, indexes={acc_b: idx_b}, documents={"sb.htm": shared_row, "fb.htm": _no_bc_document()},
        )

        assert result_a.subsidiaries_proposed == 1
        assert result_b.subsidiaries_proposed == 1

        entity_a = db.execute(select(OrgEntity).where(OrgEntity.cik == cik_a)).scalar_one()
        entity_b = db.execute(select(OrgEntity).where(OrgEntity.cik == cik_b)).scalar_one()
        sub_a = _listings_for(db, entity_a.id)[0].subsidiary_entity_id
        sub_b = _listings_for(db, entity_b.id)[0].subsidiary_entity_id
        assert sub_a != sub_b
    finally:
        cleanup_cik(db, cik_a)
        cleanup_cik(db, cik_b)
        db.close()


def test_non_table_ex21_counts_unparsed_and_stores_zero_listings():
    db = SessionLocal()
    cik = make_cik(db)
    try:
        accession = _accession(150)
        idx = index_html([{"Document": "subs.htm", "Type": "EX-21.1"}, {"Document": "f.htm", "Type": "10-K"}])
        recent = _annual_report_recent([{"form": "10-K", "accession": accession, "filing_date": "2024-01-01"}])
        body = _submissions(cik, recent=recent)
        result, _ = _run_ingest2(
            db, cik, body, indexes={accession: idx},
            documents={"subs.htm": ex21_paragraph_html(), "f.htm": _no_bc_document()},
        )
        assert result.ex21_unparsed == 1
        assert result.subsidiary_rows == 0
        entity = db.execute(select(OrgEntity).where(OrgEntity.cik == cik)).scalar_one()
        assert _listings_for(db, entity.id) == []
    finally:
        cleanup_cik(db, cik)
        db.close()


# ── Business Combinations / Acquisitions footnote ───────────────────────────

def test_footnote_takes_the_last_heading_match_and_stops_before_the_next_note():
    db = SessionLocal()
    cik = make_cik(db)
    try:
        accession = _accession(160)
        idx = index_html([{"Document": "form10k.htm", "Type": "10-K"}])
        lines = (
            ["TABLE OF CONTENTS", "Business Combinations", "Some intervening text."]
            + ["Note 4 — Business Combinations"]
            + [f"Body line {i}" for i in range(1, 13)]
            + ["Note 5 — Goodwill", "Goodwill body text that must not appear in the stored section."]
        )
        doc = text_block_html(lines)
        recent = _annual_report_recent([{"form": "10-K", "accession": accession, "filing_date": "2024-01-01"}])
        body = _submissions(cik, recent=recent)
        result, _ = _run_ingest2(db, cik, body, indexes={accession: idx}, documents={"form10k.htm": doc})

        assert result.sections_stored == 1
        assert result.sections_not_found == 0

        entity = db.execute(select(OrgEntity).where(OrgEntity.cik == cik)).scalar_one()
        sections = _sections_for(db, entity.id)
        assert len(sections) == 1
        section = sections[0]
        assert section.heading == "Note 4 — Business Combinations"
        assert section.heading_match_count == 2
        assert "Body line 1" in section.text
        assert "Goodwill body text" not in section.text
        assert section.extraction == "last_heading_match_v1"
        assert section.section == "business_combinations"
    finally:
        cleanup_cik(db, cik)
        db.close()


def test_footnote_matches_the_acquisitions_heading_variant():
    db = SessionLocal()
    cik = make_cik(db)
    try:
        accession = _accession(161)
        idx = index_html([{"Document": "form10k.htm", "Type": "10-K"}])
        lines = ["3. Acquisitions"] + [f"Body line {i}" for i in range(1, 12)]
        doc = text_block_html(lines)
        recent = _annual_report_recent([{"form": "10-K", "accession": accession, "filing_date": "2024-01-01"}])
        body = _submissions(cik, recent=recent)
        result, _ = _run_ingest2(db, cik, body, indexes={accession: idx}, documents={"form10k.htm": doc})

        assert result.sections_stored == 1
        entity = db.execute(select(OrgEntity).where(OrgEntity.cik == cik)).scalar_one()
        section = _sections_for(db, entity.id)[0]
        assert section.heading == "3. Acquisitions"
        assert section.heading_match_count == 1
    finally:
        cleanup_cik(db, cik)
        db.close()


def test_footnote_not_found_when_no_heading_matches():
    db = SessionLocal()
    cik = make_cik(db)
    try:
        accession = _accession(162)
        idx = index_html([{"Document": "form10k.htm", "Type": "10-K"}])
        doc = text_block_html(["Item 1. Business.", "Nothing about combinations here.", "Item 2. Properties."])
        recent = _annual_report_recent([{"form": "10-K", "accession": accession, "filing_date": "2024-01-01"}])
        body = _submissions(cik, recent=recent)
        result, _ = _run_ingest2(db, cik, body, indexes={accession: idx}, documents={"form10k.htm": doc})

        assert result.sections_not_found == 1
        assert result.sections_stored == 0
        entity = db.execute(select(OrgEntity).where(OrgEntity.cik == cik)).scalar_one()
        assert _sections_for(db, entity.id) == []
    finally:
        cleanup_cik(db, cik)
        db.close()


# ── oversize document handling ───────────────────────────────────────────────

def test_oversize_primary_doc_is_skipped_but_ex21_for_the_same_filing_still_processed():
    db = SessionLocal()
    cik = make_cik(db)
    try:
        accession = _accession(170)
        idx = index_html([
            {"Document": "hugefile.htm", "Type": "10-K"},
            {"Document": "subs.htm", "Type": "EX-21.1"},
        ])
        oversize_doc = "a" * (sec_edgar._MAX_EVIDENCE_BYTES + 1)
        ex21_body = html_table(tr("Name", "Jurisdiction"), tr("Example Oversize Sub LLC", "Delaware"))
        recent = _annual_report_recent([{"form": "10-K", "accession": accession, "filing_date": "2024-01-01"}])
        body = _submissions(cik, recent=recent)
        result, _ = _run_ingest2(
            db, cik, body, indexes={accession: idx}, documents={"hugefile.htm": oversize_doc, "subs.htm": ex21_body},
        )

        assert result.oversize_skipped == 1
        assert result.sections_stored == 0
        assert result.subsidiaries_proposed == 1
        assert result.ex21_docs == 1

        entity = db.execute(select(OrgEntity).where(OrgEntity.cik == cik)).scalar_one()
        assert _sections_for(db, entity.id) == []
        assert len(_listings_for(db, entity.id)) == 1

        fetch = db.execute(
            select(entity_graph.EvidenceFetch).where(entity_graph.EvidenceFetch.source_url.contains("hugefile.htm"))
        ).scalar_one_or_none()
        assert fetch is None
    finally:
        cleanup_cik(db, cik)
        db.close()


def test_invalid_primary_document_fallback_filename_is_never_requested():
    db = SessionLocal()
    cik = make_cik(db)
    try:
        accession = _accession(180)
        # No row's Type equals the form "10-K" — forces the primaryDocument
        # fallback for the footnote signal.
        idx = index_html([{"Document": "subs.htm", "Type": "EX-21.1"}])
        ex21_body = html_table(tr("Name", "Jurisdiction"), tr("Example Fallback Sub LLC", "Delaware"))
        recent = _annual_report_recent([
            {"form": "10-K", "accession": accession, "filing_date": "2024-01-01", "primary_document": "../escape.htm"},
        ])
        body = _submissions(cik, recent=recent)
        result, transport = _run_ingest2(
            db, cik, body, indexes={accession: idx}, documents={"subs.htm": ex21_body},
        )

        assert result.invalid_filename_skipped == 1
        assert result.sections_not_found == 0
        requested_leaves = [req.url.path.rsplit("/", 1)[-1] for req in transport.requests]
        assert not any(".." in leaf for leaf in requested_leaves)
        assert "escape.htm" not in requested_leaves
    finally:
        cleanup_cik(db, cik)
        db.close()


# ── form filtering ───────────────────────────────────────────────────────────

def test_10ka_is_ignored_and_10k405_is_processed():
    db = SessionLocal()
    cik = make_cik(db)
    try:
        acc_10ka, acc_10k405 = _accession(190), _accession(191)
        idx_405 = index_html([{"Document": "subs405.htm", "Type": "EX-21.1"}, {"Document": "f405.htm", "Type": "10-K405"}])
        ex21_405 = html_table(tr("Name", "Jurisdiction"), tr("Example 405 Sub LLC", "Delaware"))
        recent = _annual_report_recent([
            {"form": "10-K/A", "accession": acc_10ka, "filing_date": "2023-06-01"},
            {"form": "10-K405", "accession": acc_10k405, "filing_date": "2024-01-01"},
        ])
        body = _submissions(cik, recent=recent)
        result, transport = _run_ingest2(
            db, cik, body, indexes={acc_10k405: idx_405},
            documents={"subs405.htm": ex21_405, "f405.htm": _no_bc_document()},
        )

        assert result.annual_reports_seen == 1
        assert result.subsidiaries_proposed == 1
        requested_paths = {req.url.path for req in transport.requests}
        assert not any(acc_10ka.replace("-", "") in p for p in requested_paths)
    finally:
        cleanup_cik(db, cik)
        db.close()


# ── idempotency ───────────────────────────────────────────────────────────────

def test_reingesting_identical_bytes_for_slice2_creates_zero_new_rows():
    db = SessionLocal()
    cik = make_cik(db)
    try:
        accession = _accession(200)
        idx = index_html([{"Document": "subs.htm", "Type": "EX-21.1"}, {"Document": "f.htm", "Type": "10-K"}])
        ex21_body = html_table(tr("Name", "Jurisdiction"), tr("Example Idempotent Sub LLC", "Delaware"))
        doc = text_block_html(["Note 2 — Business Combinations"] + [f"Body {i}" for i in range(1, 12)])
        recent = _annual_report_recent([{"form": "10-K", "accession": accession, "filing_date": "2024-01-01"}])
        body = _submissions(cik, recent=recent)

        result1, _ = _run_ingest2(db, cik, body, indexes={accession: idx}, documents={"subs.htm": ex21_body, "f.htm": doc})
        assert result1.subsidiary_rows == 1
        assert result1.sections_stored == 1

        listings_before = db.query(EntitySubsidiaryListing).count()
        sections_before = db.query(EntityFilingSection).count()
        relations_before = db.query(EntityRelation).count()
        entities_before = db.query(OrgEntity).count()
        evidence_before = db.query(entity_graph.EvidenceFetch).count()

        result2, _ = _run_ingest2(db, cik, body, indexes={accession: idx}, documents={"subs.htm": ex21_body, "f.htm": doc})
        assert result2.subsidiary_rows == 0
        assert result2.subsidiaries_proposed == 0
        assert result2.subsidiaries_skipped == 1
        assert result2.sections_stored == 0
        assert result2.sections_existing == 1

        assert db.query(EntitySubsidiaryListing).count() == listings_before
        assert db.query(EntityFilingSection).count() == sections_before
        assert db.query(EntityRelation).count() == relations_before
        assert db.query(OrgEntity).count() == entities_before
        assert db.query(entity_graph.EvidenceFetch).count() == evidence_before
    finally:
        cleanup_cik(db, cik)
        db.close()


# ── posture path is live for the new observers ──────────────────────────────

def test_posture_denies_ex21_signal_when_restricting_but_not_footnote(monkeypatch):
    db = SessionLocal()
    cik = make_cik(db)
    entity_id = None
    engagement_id = None
    throwaway_observer_id = None
    try:
        entity = OrgEntity(id=uuid.uuid4(), legal_name="Example Restricted Ex21 Holdings", cik=cik)
        db.add(entity)
        db.commit()
        entity_id = entity.id

        throwaway = make_observer(db, noise_class="target_host")
        throwaway_observer_id = throwaway.id
        engagement = make_engagement(db, posture=EngagementPosture.PRE_CLOSE.value, subject_entity_id=entity.id)
        engagement_id = engagement.id

        # Precondition check — see slice 1's identical pattern.
        assert db.get(OrgEntity, entity_id) is not None
        assert posture.posture_restricts(engagement.posture) is True

        monkeypatch.setattr(edgar_ingest, "OBSERVER_EX21", throwaway.name)

        accession = _accession(210)
        idx = index_html([{"Document": "subs.htm", "Type": "EX-21.1"}, {"Document": "f.htm", "Type": "10-K"}])
        ex21_body = html_table(tr("Name", "Jurisdiction"), tr("Example Restricted Sub LLC", "Delaware"))
        recent = _annual_report_recent([{"form": "10-K", "accession": accession, "filing_date": "2024-01-01"}])
        body = _submissions(cik, name="Example Restricted Ex21 Holdings", recent=recent)
        result, _ = _run_ingest2(
            db, cik, body, indexes={accession: idx}, documents={"subs.htm": ex21_body, "f.htm": _no_bc_document()},
        )

        assert throwaway.name in result.denied
        assert result.subsidiary_rows == 0
        assert result.ex21_docs == 0
        assert _listings_for(db, entity_id) == []
    finally:
        cleanup_engagement(db, engagement_id)
        cleanup_cik(db, cik)
        cleanup_observer(db, throwaway_observer_id)
        db.close()


def test_posture_control_ex21_signal_runs_without_a_restricting_engagement(monkeypatch):
    """Paired with the test above, same setup minus the engagement — proves
    the denial above is not vacuous."""
    db = SessionLocal()
    cik = make_cik(db)
    throwaway_observer_id = None
    try:
        throwaway = make_observer(db, noise_class="target_host")
        throwaway_observer_id = throwaway.id
        monkeypatch.setattr(edgar_ingest, "OBSERVER_EX21", throwaway.name)

        accession = _accession(211)
        idx = index_html([{"Document": "subs.htm", "Type": "EX-21.1"}, {"Document": "f.htm", "Type": "10-K"}])
        ex21_body = html_table(tr("Name", "Jurisdiction"), tr("Example Unrestricted Ex21 Sub LLC", "Delaware"))
        recent = _annual_report_recent([{"form": "10-K", "accession": accession, "filing_date": "2024-01-01"}])
        body = _submissions(cik, name="Example Unrestricted Ex21 Holdings", recent=recent)
        result, _ = _run_ingest2(
            db, cik, body, indexes={accession: idx}, documents={"subs.htm": ex21_body, "f.htm": _no_bc_document()},
        )

        assert result.denied == []
        assert result.subsidiary_rows == 1
    finally:
        cleanup_cik(db, cik)
        cleanup_observer(db, throwaway_observer_id)
        db.close()


# ═════════════════════════════════════════════════════════════════════════
# planning#220 — live-run defects: 404 aborts ingest, iXBRL filename,
# heading/section-end rules. Reuses `_EdgarTransport`'s `document_statuses`/
# `index_statuses` (added for this issue) to script a specific document's
# or index's HTTP status without needing a new transport class.
# ═════════════════════════════════════════════════════════════════════════


# ── defect 1: per-document failures skip and continue; 403/exhausted-429
# still abort ─────────────────────────────────────────────────────────────

def test_404_on_an_exhibit_is_skipped_and_a_later_filing_still_stores():
    """The #220 blocker itself: the OLDER 10-K's EX-21 404s, and the ingest
    must still reach and store the NEWER filing's listings and section."""
    db = SessionLocal()
    cik = make_cik(db)
    try:
        acc_old, acc_new = _accession(400), _accession(401)
        idx_old = index_html([
            {"Document": "oldsub.htm", "Type": "EX-21.1"},
            {"Document": "oldform.htm", "Type": "10-K"},
        ])
        idx_new = index_html([
            {"Document": "newsub.htm", "Type": "EX-21.1"},
            {"Document": "newform.htm", "Type": "10-K"},
        ])
        new_ex21_body = html_table(tr("Name", "Jurisdiction"), tr("Example New Sub LLC", "Delaware"))
        new_doc = text_block_html(["Note 4 — Business Combinations"] + [f"Body line {i}" for i in range(1, 12)])
        recent = _annual_report_recent([
            {"form": "10-K", "accession": acc_old, "filing_date": "2000-01-01"},
            {"form": "10-K", "accession": acc_new, "filing_date": "2024-01-01"},
        ])
        body = _submissions(cik, recent=recent)
        result, transport = _run_ingest2(
            db, cik, body,
            indexes={acc_old: idx_old, acc_new: idx_new},
            documents={"oldform.htm": _no_bc_document(), "newsub.htm": new_ex21_body, "newform.htm": new_doc},
            document_statuses={"oldsub.htm": 404},
        )

        assert result.documents_not_found == 1
        assert result.documents_fetch_failed == 0

        requested_leaves = {req.url.path.rsplit("/", 1)[-1] for req in transport.requests}
        assert "oldsub.htm" in requested_leaves, "the 404'd exhibit must actually have been requested"

        entity = db.execute(select(OrgEntity).where(OrgEntity.cik == cik)).scalar_one()
        listings = _listings_for(db, entity.id)
        assert any(l.name == "Example New Sub LLC" for l in listings), "the newer filing's EX-21 must still be stored"
        sections = _sections_for(db, entity.id)
        assert len(sections) == 1
        assert sections[0].accession_number == acc_new
        assert "Body line 1" in sections[0].text
    finally:
        cleanup_cik(db, cik)
        db.close()


def test_5xx_exhausted_on_an_exhibit_is_skipped_and_a_later_filing_still_stores():
    """Same shape as the 404 test above, but a transient 5xx exhausted after
    retries — `documents_fetch_failed`, not `documents_not_found`."""
    db = SessionLocal()
    cik = make_cik(db)
    try:
        acc_old, acc_new = _accession(402), _accession(403)
        idx_old = index_html([
            {"Document": "oldsub.htm", "Type": "EX-21.1"},
            {"Document": "oldform.htm", "Type": "10-K"},
        ])
        idx_new = index_html([
            {"Document": "newsub.htm", "Type": "EX-21.1"},
            {"Document": "newform.htm", "Type": "10-K"},
        ])
        new_ex21_body = html_table(tr("Name", "Jurisdiction"), tr("Example Newer Sub LLC", "Delaware"))
        new_doc = text_block_html(["Note 5 — Business Combinations"] + [f"Body line {i}" for i in range(1, 12)])
        recent = _annual_report_recent([
            {"form": "10-K", "accession": acc_old, "filing_date": "2001-01-01"},
            {"form": "10-K", "accession": acc_new, "filing_date": "2024-02-02"},
        ])
        body = _submissions(cik, recent=recent)
        result, transport = _run_ingest2(
            db, cik, body,
            indexes={acc_old: idx_old, acc_new: idx_new},
            documents={"oldform.htm": _no_bc_document(), "newsub.htm": new_ex21_body, "newform.htm": new_doc},
            document_statuses={"oldsub.htm": 503},
        )

        assert result.documents_fetch_failed == 1
        assert result.documents_not_found == 0

        requested_leaves = [req.url.path.rsplit("/", 1)[-1] for req in transport.requests]
        assert requested_leaves.count("oldsub.htm") == sec_edgar._MAX_ATTEMPTS

        entity = db.execute(select(OrgEntity).where(OrgEntity.cik == cik)).scalar_one()
        assert any(l.name == "Example Newer Sub LLC" for l in _listings_for(db, entity.id))
        assert len(_sections_for(db, entity.id)) == 1
    finally:
        cleanup_cik(db, cik)
        db.close()


def test_404_on_the_per_filing_index_counts_and_footnote_still_uses_primary_document():
    db = SessionLocal()
    cik = make_cik(db)
    try:
        accession = _accession(404)
        doc = text_block_html(["Note 2 — Business Combinations"] + [f"Body {i}" for i in range(1, 12)])
        recent = _annual_report_recent([
            {"form": "10-K", "accession": accession, "filing_date": "2024-01-01", "primary_document": "fallback10k.htm"},
        ])
        body = _submissions(cik, recent=recent)
        # No entry for `accession` in `indexes` — `_EdgarTransport` already
        # 404s an unlisted index accession.
        result, transport = _run_ingest2(db, cik, body, indexes={}, documents={"fallback10k.htm": doc})

        assert result.documents_not_found == 1
        assert result.sections_stored == 1
        assert result.ex21_missing == 0  # never reached — no index to look up EX-21 by Type

        requested_leaves = {req.url.path.rsplit("/", 1)[-1] for req in transport.requests}
        assert "fallback10k.htm" in requested_leaves

        entity = db.execute(select(OrgEntity).where(OrgEntity.cik == cik)).scalar_one()
        section = _sections_for(db, entity.id)[0]
        assert "Body 1" in section.text
    finally:
        cleanup_cik(db, cik)
        db.close()


def test_403_on_an_exhibit_aborts_ingest_before_the_later_filing():
    db = SessionLocal()
    cik = make_cik(db)
    try:
        acc_old, acc_new = _accession(405), _accession(406)
        idx_old = index_html([
            {"Document": "forbidden.htm", "Type": "EX-21.1"},
            {"Document": "oldform.htm", "Type": "10-K"},
        ])
        idx_new = index_html([
            {"Document": "newsub.htm", "Type": "EX-21.1"},
            {"Document": "newform.htm", "Type": "10-K"},
        ])
        recent = _annual_report_recent([
            {"form": "10-K", "accession": acc_old, "filing_date": "2000-01-01"},
            {"form": "10-K", "accession": acc_new, "filing_date": "2024-01-01"},
        ])
        body = _submissions(cik, recent=recent)
        transport = _EdgarTransport(
            main_body=body,
            indexes={acc_old: idx_old, acc_new: idx_new},
            documents={
                "oldform.htm": _no_bc_document(),
                "newsub.htm": "MUST NEVER BE FETCHED",
                "newform.htm": "MUST NEVER BE FETCHED",
            },
            document_statuses={"forbidden.htm": 403},
        )
        sec_edgar._transport = transport.transport
        sec_edgar._sleep = lambda _s: None
        try:
            with pytest.raises(sec_edgar.SecForbidden):
                edgar_ingest.ingest_cik(db, cik)
        finally:
            sec_edgar._transport = None
            sec_edgar._sleep = __import__("time").sleep

        requested_leaves = {req.url.path.rsplit("/", 1)[-1] for req in transport.requests}
        assert "newsub.htm" not in requested_leaves
        assert "newform.htm" not in requested_leaves
        assert acc_new.replace("-", "") not in "".join(req.url.path for req in transport.requests)
    finally:
        cleanup_cik(db, cik)
        db.close()


def test_429_exhausted_on_an_exhibit_aborts_ingest_before_the_later_filing():
    db = SessionLocal()
    cik = make_cik(db)
    try:
        acc_old, acc_new = _accession(407), _accession(408)
        idx_old = index_html([
            {"Document": "ratelimited.htm", "Type": "EX-21.1"},
            {"Document": "oldform.htm", "Type": "10-K"},
        ])
        idx_new = index_html([
            {"Document": "newsub.htm", "Type": "EX-21.1"},
            {"Document": "newform.htm", "Type": "10-K"},
        ])
        recent = _annual_report_recent([
            {"form": "10-K", "accession": acc_old, "filing_date": "2000-06-01"},
            {"form": "10-K", "accession": acc_new, "filing_date": "2024-03-03"},
        ])
        body = _submissions(cik, recent=recent)
        transport = _EdgarTransport(
            main_body=body,
            indexes={acc_old: idx_old, acc_new: idx_new},
            documents={
                "oldform.htm": _no_bc_document(),
                "newsub.htm": "MUST NEVER BE FETCHED",
                "newform.htm": "MUST NEVER BE FETCHED",
            },
            document_statuses={"ratelimited.htm": 429},
        )
        sec_edgar._transport = transport.transport
        sec_edgar._sleep = lambda _s: None
        try:
            with pytest.raises(sec_edgar.SecRateLimited):
                edgar_ingest.ingest_cik(db, cik)
        finally:
            sec_edgar._transport = None
            sec_edgar._sleep = __import__("time").sleep

        requested_leaves = {req.url.path.rsplit("/", 1)[-1] for req in transport.requests}
        assert "newsub.htm" not in requested_leaves
        assert "newform.htm" not in requested_leaves
    finally:
        cleanup_cik(db, cik)
        db.close()


# ── defect 2: iXBRL viewer-token stripping + primaryDocument fallback ──────

@pytest.mark.parametrize(
    "cell,expected",
    [
        ("a.htm iXBRL", "a.htm"),
        ("a.htm", "a.htm"),
        ("iXBRL", "iXBRL"),
        ("a.htm ixbrl", "a.htm ixbrl"),
    ],
)
def test_document_filename_helper_cases(cell, expected):
    assert edgar_ingest._document_filename(cell) == expected


def test_ixbrl_document_cell_yields_the_filename_and_is_fetched():
    db = SessionLocal()
    cik = make_cik(db)
    try:
        accession = _accession(410)
        idx = index_html([
            {"Document": '<a href="/ix?doc=/Archives/edgar/data/1/2/x10k.htm">x10k.htm</a> <span>iXBRL</span>', "Type": "10-K"},
        ])
        doc = text_block_html(["Note 1 — Business Combinations"] + [f"Body {i}" for i in range(1, 12)])
        recent = _annual_report_recent([{"form": "10-K", "accession": accession, "filing_date": "2024-01-01"}])
        body = _submissions(cik, recent=recent)
        result, transport = _run_ingest2(db, cik, body, indexes={accession: idx}, documents={"x10k.htm": doc})

        assert result.sections_stored == 1
        assert result.invalid_filename_skipped == 0
        requested_leaves = {req.url.path.rsplit("/", 1)[-1] for req in transport.requests}
        assert "x10k.htm" in requested_leaves
    finally:
        cleanup_cik(db, cik)
        db.close()


def test_invalid_document_cell_falls_back_to_primary_document():
    db = SessionLocal()
    cik = make_cik(db)
    try:
        accession = _accession(411)
        idx = index_html([{"Document": "bad name!.htm", "Type": "10-K"}])
        doc = text_block_html(["Note 1 — Business Combinations"] + [f"Body {i}" for i in range(1, 12)])
        recent = _annual_report_recent([
            {"form": "10-K", "accession": accession, "filing_date": "2024-01-01", "primary_document": "fallback.htm"},
        ])
        body = _submissions(cik, recent=recent)
        result, transport = _run_ingest2(db, cik, body, indexes={accession: idx}, documents={"fallback.htm": doc})

        assert result.sections_stored == 1
        assert result.invalid_filename_skipped == 0
        requested_leaves = [req.url.path.rsplit("/", 1)[-1] for req in transport.requests]
        assert not any("bad name" in leaf for leaf in requested_leaves)
        assert "fallback.htm" in requested_leaves
    finally:
        cleanup_cik(db, cik)
        db.close()


# ── defect 3: prefer a numbered heading match, LAST among those ───────────

def test_bare_table_cell_acquisitions_after_the_real_note_is_not_picked():
    """Live-run shape: a bare `Acquisitions` COLUMN HEADER in the following
    note's goodwill roll-forward table must not beat the real, numbered
    `NOTE n — BUSINESS COMBINATIONS` heading."""
    db = SessionLocal()
    cik = make_cik(db)
    try:
        accession = _accession(420)
        idx = index_html([{"Document": "form10k.htm", "Type": "10-K"}])
        before = ["TABLE OF CONTENTS", "Business Combinations", "NOTE 4 — BUSINESS COMBINATIONS"]
        body_lines = [f"Body line {i}" for i in range(1, 13)]
        p_before = "".join(f"<p>{l}</p>" for l in before + body_lines)
        p_note5 = "<p>NOTE 5 — GOODWILL</p>"
        # Each bare "Acquisitions" cell sits alone in its own <tr>/<table>
        # so it renders as its OWN line — a real roll-forward table's
        # header row space-joins its cells into one non-matching line, but
        # the live defect (planning#220) was two SEPARATE such matches, so
        # this fixture isolates each one to exercise the same code path
        # deterministically.
        goodwill_table = "<table><tr><td>Acquisitions</td></tr></table><table><tr><td>Acquisitions</td></tr></table>"
        p_after = "<p>Goodwill body text that must not appear in the stored section.</p>"
        doc = f"<html><body>{p_before}{p_note5}{goodwill_table}{p_after}</body></html>"

        recent = _annual_report_recent([{"form": "10-K", "accession": accession, "filing_date": "2024-01-01"}])
        submissions_body = _submissions(cik, recent=recent)
        result, _ = _run_ingest2(db, cik, submissions_body, indexes={accession: idx}, documents={"form10k.htm": doc})

        assert result.sections_stored == 1
        entity = db.execute(select(OrgEntity).where(OrgEntity.cik == cik)).scalar_one()
        section = _sections_for(db, entity.id)[0]
        assert section.heading == "NOTE 4 — BUSINESS COMBINATIONS"
        assert section.heading_match_count == 4
        assert "Body line 1" in section.text
        assert "Goodwill body text" not in section.text
        assert "NOTE 5" not in section.text
    finally:
        cleanup_cik(db, cik)
        db.close()


def test_bare_only_document_still_takes_the_last_bare_match():
    """No numbered match anywhere — the original LAST-bare-match rule still
    applies unchanged."""
    db = SessionLocal()
    cik = make_cik(db)
    try:
        accession = _accession(421)
        idx = index_html([{"Document": "form10k.htm", "Type": "10-K"}])
        lines = (
            ["Acquisitions"]
            + [f"Filler {i}" for i in range(1, 11)]
            + ["Business Combinations"]
            + [f"Body {i}" for i in range(1, 12)]
        )
        doc = text_block_html(lines)
        recent = _annual_report_recent([{"form": "10-K", "accession": accession, "filing_date": "2024-01-01"}])
        body = _submissions(cik, recent=recent)
        result, _ = _run_ingest2(db, cik, body, indexes={accession: idx}, documents={"form10k.htm": doc})

        assert result.sections_stored == 1
        entity = db.execute(select(OrgEntity).where(OrgEntity.cik == cik)).scalar_one()
        section = _sections_for(db, entity.id)[0]
        assert section.heading == "Business Combinations"
        assert section.heading_match_count == 2
    finally:
        cleanup_cik(db, cik)
        db.close()


def test_multiple_numbered_matches_take_the_last_one():
    db = SessionLocal()
    cik = make_cik(db)
    try:
        accession = _accession(422)
        idx = index_html([{"Document": "form10k.htm", "Type": "10-K"}])
        lines = (
            ["Note 3 — Acquisitions"]
            + [f"Filler {i}" for i in range(1, 11)]
            + ["Note 4 — Acquisitions"]
            + [f"Body {i}" for i in range(1, 12)]
        )
        doc = text_block_html(lines)
        recent = _annual_report_recent([{"form": "10-K", "accession": accession, "filing_date": "2024-01-01"}])
        body = _submissions(cik, recent=recent)
        result, _ = _run_ingest2(db, cik, body, indexes={accession: idx}, documents={"form10k.htm": doc})

        assert result.sections_stored == 1
        entity = db.execute(select(OrgEntity).where(OrgEntity.cik == cik)).scalar_one()
        section = _sections_for(db, entity.id)[0]
        assert section.heading == "Note 4 — Acquisitions"
        assert section.heading_match_count == 2
    finally:
        cleanup_cik(db, cik)
        db.close()


# ── defect 4: section end follows the start's shape; running headers never
# end a section ────────────────────────────────────────────────────────────

def test_numbered_section_ignores_part_ii_and_all_caps_lines_ends_only_on_next_note():
    db = SessionLocal()
    cik = make_cik(db)
    try:
        accession = _accession(430)
        idx = index_html([{"Document": "form10k.htm", "Type": "10-K"}])
        lines = (
            ["NOTE 6 — BUSINESS COMBINATIONS"]
            + [f"Body line {i}" for i in range(1, 15)]
            + ["PART II", "CONSOLIDATED FINANCIAL STATEMENTS"]
            + [f"Body line {i}" for i in range(15, 25)]
            + ["NOTE 7 — INCOME TAXES"]
            + ["Unrelated tax body."]
        )
        doc = text_block_html(lines)
        recent = _annual_report_recent([{"form": "10-K", "accession": accession, "filing_date": "2024-01-01"}])
        body = _submissions(cik, recent=recent)
        result, _ = _run_ingest2(db, cik, body, indexes={accession: idx}, documents={"form10k.htm": doc})

        assert result.sections_stored == 1
        entity = db.execute(select(OrgEntity).where(OrgEntity.cik == cik)).scalar_one()
        section = _sections_for(db, entity.id)[0]
        assert "PART II" in section.text
        assert "CONSOLIDATED FINANCIAL STATEMENTS" in section.text
        assert "Body line 20" in section.text
        assert "Unrelated tax body." not in section.text
    finally:
        cleanup_cik(db, cik)
        db.close()


def test_bare_section_excludes_part_ii_but_ends_on_a_real_all_caps_heading():
    db = SessionLocal()
    cik = make_cik(db)
    try:
        accession = _accession(431)
        idx = index_html([{"Document": "form10k.htm", "Type": "10-K"}])
        lines = (
            ["Business Combinations"]
            + [f"Body line {i}" for i in range(1, 15)]
            + ["PART II"]
            + [f"Body line {i}" for i in range(15, 18)]
            + ["GOODWILL AND INTANGIBLE ASSETS"]
            + ["Goodwill text that must not appear."]
        )
        doc = text_block_html(lines)
        recent = _annual_report_recent([{"form": "10-K", "accession": accession, "filing_date": "2024-01-01"}])
        body = _submissions(cik, recent=recent)
        result, _ = _run_ingest2(db, cik, body, indexes={accession: idx}, documents={"form10k.htm": doc})

        assert result.sections_stored == 1
        entity = db.execute(select(OrgEntity).where(OrgEntity.cik == cik)).scalar_one()
        section = _sections_for(db, entity.id)[0]
        assert "PART II" in section.text
        assert "Body line 16" in section.text
        assert "Goodwill text that must not appear." not in section.text
    finally:
        cleanup_cik(db, cik)
        db.close()


# ═════════════════════════════════════════════════════════════════════════
# planning#216 — the filer's own website, read from the SAME primary 10-K
# document the footnote reader already fetches.
# ═════════════════════════════════════════════════════════════════════════


def _website_document(domain: str) -> str:
    return text_block_html(
        [
            "Item 1. Business.",
            f"Available Information. Our website address is www.{domain}. Information on it is not part of this report.",
            "We also work with vendors such as www.vendor-cd216.example.",
        ]
    )


def test_website_candidate_is_proposed_from_the_shared_primary_document_fetch():
    from app.models.candidate_domain import CandidateDomain
    from app.models.target import Target

    db = SessionLocal()
    cik = make_cik(db)
    domain = f"holdings-{uuid.uuid4().hex[:8]}.example"
    try:
        a1, a2 = _accession(316), _accession(317)
        recent = _annual_report_recent(
            [
                {"form": "10-K", "accession": a2, "filing_date": "2024-02-01"},
                {"form": "10-K", "accession": a1, "filing_date": "2020-02-01"},
            ]
        )
        body = _submissions(cik, recent=recent)
        result, transport = _run_ingest2(
            db, cik, body,
            indexes={
                a1: index_html([{"Document": "k2020.htm", "Type": "10-K"}]),
                a2: index_html([{"Document": "k2024.htm", "Type": "10-K"}]),
            },
            documents={"k2020.htm": _website_document(domain), "k2024.htm": _website_document(domain)},
        )

        # One fetch per 10-K, shared by both readers — the website reader
        # adds no request of its own.
        leaves = [r.url.path.rsplit("/", 1)[-1] for r in transport.requests]
        assert leaves.count("k2020.htm") == 1 and leaves.count("k2024.htm") == 1
        assert result.website_candidates_proposed == 1
        assert result.website_candidates_existing == 1

        entity = db.execute(select(OrgEntity).where(OrgEntity.cik == cik)).scalar_one()
        rows = db.execute(select(CandidateDomain).where(CandidateDomain.entity_id == entity.id)).scalars().all()
        # The vendor domain is in the same document but not after an own-site anchor.
        assert [r.domain for r in rows] == [domain]
        row = rows[0]
        assert (row.status, row.source, row.first_cited_on, row.last_cited_on) == (
            "proposed", "edgar_10k_website", date(2020, 2, 1), date(2024, 2, 1),
        )
        # Cites the FIRST 10-K that named it (ingest runs oldest-first).
        from app.models.evidence import EvidenceFetch

        assert db.get(EvidenceFetch, row.evidence_id).source_url.endswith("/k2020.htm")
        assert row.observer_id == _observer_by_name(db, "edgar_10k_website").id
        # A candidate is never scope.
        assert db.query(Target).filter(Target.value == domain).count() == 0
    finally:
        cleanup_cik(db, cik)
        db.close()


def test_posture_denies_website_signal_when_restricting_but_not_footnote(monkeypatch):
    from app.models.candidate_domain import CandidateDomain

    db = SessionLocal()
    cik = make_cik(db)
    engagement_id = None
    throwaway_observer_id = None
    domain = f"restricted-{uuid.uuid4().hex[:8]}.example"
    try:
        entity = OrgEntity(id=uuid.uuid4(), legal_name="Example Restricted Web Holdings", cik=cik)
        db.add(entity)
        db.commit()
        throwaway = make_observer(db, noise_class="target_host")
        throwaway_observer_id = throwaway.id
        engagement_id = make_engagement(db, posture=EngagementPosture.PRE_CLOSE.value, subject_entity_id=entity.id).id
        monkeypatch.setattr(edgar_ingest, "OBSERVER_WEBSITE", throwaway.name)

        accession = _accession(318)
        lines = ["Note 3 — Acquisitions"] + [f"Body line {i}" for i in range(12)] + [
            f"Our website is www.{domain}."
        ]
        recent = _annual_report_recent([{"form": "10-K", "accession": accession, "filing_date": "2024-01-01"}])
        result, _ = _run_ingest2(
            db, cik, _submissions(cik, name="Example Restricted Web Holdings", recent=recent),
            indexes={accession: index_html([{"Document": "f.htm", "Type": "10-K"}])},
            documents={"f.htm": text_block_html(lines)},
        )

        assert throwaway.name in result.denied
        assert result.website_candidates_proposed == 0
        assert db.query(CandidateDomain).filter(CandidateDomain.entity_id == entity.id).count() == 0
        # The footnote reader, NOT denied, still ran over the same document.
        assert result.sections_stored == 1
    finally:
        cleanup_engagement(db, engagement_id)
        cleanup_cik(db, cik)
        cleanup_observer(db, throwaway_observer_id)
        db.close()


def test_posture_control_website_signal_runs_without_a_restricting_engagement(monkeypatch):
    """Paired with the test above, minus the engagement — proves that
    denial is not vacuous (the same document DOES yield a candidate)."""
    db = SessionLocal()
    cik = make_cik(db)
    throwaway_observer_id = None
    domain = f"unrestricted-{uuid.uuid4().hex[:8]}.example"
    try:
        throwaway = make_observer(db, noise_class="target_host")
        throwaway_observer_id = throwaway.id
        monkeypatch.setattr(edgar_ingest, "OBSERVER_WEBSITE", throwaway.name)

        accession = _accession(319)
        lines = ["Note 3 — Acquisitions"] + [f"Body line {i}" for i in range(12)] + [
            f"Our website is www.{domain}."
        ]
        recent = _annual_report_recent([{"form": "10-K", "accession": accession, "filing_date": "2024-01-01"}])
        result, _ = _run_ingest2(
            db, cik, _submissions(cik, recent=recent),
            indexes={accession: index_html([{"Document": "f.htm", "Type": "10-K"}])},
            documents={"f.htm": text_block_html(lines)},
        )
        assert result.denied == []
        assert result.website_candidates_proposed == 1
    finally:
        cleanup_cik(db, cik)
        cleanup_observer(db, throwaway_observer_id)
        db.close()
