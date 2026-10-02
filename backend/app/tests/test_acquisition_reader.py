"""Coverage for planning#218: the AI acquisition reader
(`app.services.acquisition_reader`), its endpoints, and migration 0066's
run `kind`.

Recorded fixtures only: every LLM response is scripted on
`llm_connector._transport` (an `httpx.MockTransport`), and the assertions
read what the TRANSPORT received, never a wrapper. No live call, no real
company: names are invented, CIKs come from `make_cik`'s "99" range, and
every row is deleted by id/CIK afterwards.

Run with:  backend/scripts/test.ps1 app/tests/test_acquisition_reader.py
"""

import json
import uuid
from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError

from app.core.database import SessionLocal
from app.main import app
from app.models.engagement import Engagement
from app.models.entity_filing_section import EntityFilingSection
from app.models.entity_ingest_run import EntityIngestRun
from app.models.entity_relation import EntityRelation
from app.models.llm_call import LlmCall
from app.models.observer import Observer
from app.models.org_entity import OrgEntity
from app.models.user import UserRole
from app.services import acquisition_reader as ar
from app.services import entity_graph
from app.services import llm_connector as llmc
from app.tests._edgar import cleanup_cik, make_cik
from app.tests._engagement import make_engagement
from app.tests._entity_graph import make_evidence
from app.tests.test_edgar_ingest_api import _cleanup_user, _make_user
from app.tests.test_llm_connector import (
    _configure_openrouter,
    _error_response,
    _ok_response,
    _restore_openrouter,
    _ScriptedTransport,
)

client = TestClient(app)

FILER_NAME = "Example Acquirer Holdings"

S1 = (
    "Note 3. Business Combinations\n"
    "On March 15, 2021, the Company acquired Examplar Widgets for $12 million in cash.\n"
    "In August 2022, the Company completed its acquisition of Fictive Gadget Labs.\n"
    "Goodwill from these deals is not deductible for tax purposes.\n"
)
S2 = (
    "Note 4. Acquisitions\n"
    "The Company acquired Placeholder Sprockets in 2023.\n"
    "On March 15, 2021, the Company acquired Examplar Widgets for $12 million in cash.\n"
)
Q_WIDGETS = "On March 15, 2021, the Company acquired Examplar Widgets for $12 million in cash."
Q_GADGETS = "In August 2022, the Company completed its acquisition of Fictive Gadget Labs."
Q_SPROCKETS = "The Company acquired Placeholder Sprockets in 2023."


def _item(name: str, quote: str, date_text: str | None = None) -> dict:
    return {"acquired_name": name, "deal_date_text": date_text, "quote": quote}


def _answer(*items: dict, cost: float | None = None) -> httpx.Response:
    return _ok_response(content=json.dumps({"acquisitions": list(items)}), cost=cost)


# ── fixtures ────────────────────────────────────────────────────────────────

class _Filer:
    """One invented filer (CIK'd entity) with stored sections, plus
    everything a test creates around it, cleaned up in `close`."""

    def __init__(self):
        db = SessionLocal()
        try:
            self.cik = make_cik(db)
            self.entity_id = uuid.uuid4()
            db.add(OrgEntity(id=self.entity_id, legal_name=FILER_NAME, cik=self.cik))
            db.commit()
            self.footnote_observer_id = db.query(Observer.id).filter(Observer.name == "edgar_10k_footnote").scalar()
        finally:
            db.close()
        self.sections: list[EntityFilingSection] = []
        self.engagement_ids: list[uuid.UUID] = []
        self.extra_entity_ids: list[uuid.UUID] = []
        self.run_ids: list[uuid.UUID] = []

    def add_section(self, text: str, *, filing_date: date) -> EntityFilingSection:
        db = SessionLocal()
        try:
            n = len(self.sections) + 1
            evidence = make_evidence(
                db, content=f"{uuid.uuid4()} {text}".encode(),
                source_url=f"https://www.sec.gov/Archives/edgar/data/{self.cik}/doc{n}.htm",
            )
            section = EntityFilingSection(
                id=uuid.uuid4(), entity_id=self.entity_id, observer_id=self.footnote_observer_id,
                evidence_id=evidence.id, accession_number=f"99000002{n:02d}-24-{n:06d}", form="10-K",
                filing_date=filing_date, report_date=None, section="business_combinations",
                extraction="test", heading=text.splitlines()[0], heading_match_count=1,
                start_line=0, end_line=len(text.splitlines()), text=text,
            )
            db.add(section)
            db.commit()
            db.refresh(section)
            db.expunge(section)
        finally:
            db.close()
        self.sections.append(section)
        return section

    def read(self) -> ar.ReadResult:
        run_id = uuid.uuid4()
        self.run_ids.append(run_id)
        db = SessionLocal()
        try:
            return ar.read_acquisitions(db, entity_id=self.entity_id, run_id=run_id)
        finally:
            db.close()

    def acquired_rows(self) -> list[tuple[EntityRelation, OrgEntity]]:
        db = SessionLocal()
        try:
            rows = (
                db.query(EntityRelation, OrgEntity)
                .join(OrgEntity, OrgEntity.id == EntityRelation.object_id)
                .filter(EntityRelation.subject_id == self.entity_id, EntityRelation.relation == "acquired")
                .order_by(OrgEntity.legal_name)
                .all()
            )
            for r, e in rows:
                db.expunge(r)
                db.expunge(e)
            return rows
        finally:
            db.close()

    def close(self) -> None:
        db = SessionLocal()
        try:
            labels = [ar.task_label(r) for r in self.run_ids]
            labels += [
                ar.task_label(r.id) for r in db.query(EntityIngestRun).filter(EntityIngestRun.cik == self.cik).all()
            ]
            if labels:
                db.query(LlmCall).filter(LlmCall.task.in_(labels)).delete(synchronize_session=False)
                db.commit()
            if self.engagement_ids:
                db.query(Engagement).filter(Engagement.id.in_(self.engagement_ids)).delete(synchronize_session=False)
                db.commit()
            cleanup_cik(db, self.cik)
            if self.extra_entity_ids:
                db.query(OrgEntity).filter(OrgEntity.id.in_(self.extra_entity_ids)).delete(synchronize_session=False)
                db.commit()
        finally:
            db.close()


@pytest.fixture
def filer():
    f = _Filer()
    yield f
    f.close()


@pytest.fixture
def openrouter():
    db = SessionLocal()
    try:
        snapshot = _configure_openrouter(db)
    finally:
        db.close()
    yield
    _restore_openrouter(snapshot)


@pytest.fixture
def scripted(openrouter):
    """`scripted(responses)` installs a transport serving them in order and
    returns it, so the test can read `.requests`."""
    holder: list[_ScriptedTransport] = []

    def install(responses):
        t = _ScriptedTransport(responses)
        llmc._transport = t.transport
        holder.append(t)
        return t

    yield install
    llmc._transport = None


def _user_contents(t: _ScriptedTransport) -> list[str]:
    return [json.loads(r.content)["messages"][-1]["content"] for r in t.requests]


# ── the read ────────────────────────────────────────────────────────────────

def test_proposes_grounded_acquisitions_oldest_filing_first(filer, scripted):
    filer.add_section(S2, filing_date=date(2024, 2, 1))
    filer.add_section(S1, filing_date=date(2023, 2, 1))
    t = scripted([
        _answer(_item("Examplar Widgets", Q_WIDGETS, "March 15, 2021"), _item("Fictive Gadget Labs", Q_GADGETS, "August 2022")),
        _answer(_item("Placeholder Sprockets", Q_SPROCKETS, "2023"), _item("Examplar Widgets", Q_WIDGETS, "March 15, 2021")),
    ])

    result = filer.read()

    # One request per section, oldest filing first, each carrying exactly that
    # section's text.
    assert _user_contents(t) == [S1, S2]
    assert (result.sections_read, result.proposed, result.items_existing) == (2, 3, 1)

    rows = {e.legal_name: r for r, e in filer.acquired_rows()}
    assert set(rows) == {"Examplar Widgets", "Fictive Gadget Labs", "Placeholder Sprockets"}
    s1, s2 = sorted(filer.sections, key=lambda s: s.filing_date)
    db = SessionLocal()
    try:
        observer = db.query(Observer).filter(Observer.name == ar.OBSERVER).one()
        assert observer.trust == "inferred" and observer.confirms_relations is False
    finally:
        db.close()
    for r in rows.values():
        assert r.status == "proposed"
        assert r.decision_kind is None
        assert r.grounding == "verified"
        assert r.observer_id == observer.id
    # The repeat of Examplar Widgets in the LATER 10-K cites the earlier one.
    assert rows["Examplar Widgets"].evidence_id == s1.evidence_id
    assert rows["Placeholder Sprockets"].evidence_id == s2.evidence_id
    assert rows["Examplar Widgets"].quote == Q_WIDGETS
    assert (rows["Examplar Widgets"].event_date, rows["Examplar Widgets"].event_date_precision) == (date(2021, 3, 15), "day")
    assert (rows["Fictive Gadget Labs"].event_date, rows["Fictive Gadget Labs"].event_date_precision) == (date(2022, 8, 1), "month")
    assert (rows["Placeholder Sprockets"].event_date, rows["Placeholder Sprockets"].event_date_precision) == (date(2023, 1, 1), "year")


def test_an_ungrounded_item_is_dropped_and_the_rest_survive_without_a_retry(filer, scripted):
    filer.add_section(S1, filing_date=date(2023, 2, 1))
    t = scripted([
        _answer(
            _item("Examplar Widgets", Q_WIDGETS),
            _item("Nonexistent Holdings", "The Company acquired Nonexistent Holdings in 2020."),
        ),
    ])

    result = filer.read()

    # ONE request: a bad item is dropped here, per item. It must not make the
    # connector reject the whole list and retry, which is what whole-value
    # grounding would do if the schema's fields were `Grounded`.
    assert len(t.requests) == 1
    assert (result.items_returned, result.items_ungrounded, result.proposed) == (2, 1, 1)
    assert [e.legal_name for _, e in filer.acquired_rows()] == ["Examplar Widgets"]


def test_a_real_quote_with_an_invented_name_is_dropped(filer, scripted):
    filer.add_section(S1, filing_date=date(2023, 2, 1))
    scripted([_answer(_item("Invented Rival Corp", Q_WIDGETS))])

    result = filer.read()

    assert (result.items_ungrounded, result.proposed) == (1, 0)
    assert filer.acquired_rows() == []


def test_a_rejection_is_never_re_proposed(filer, scripted):
    """planning#213's invariant (mutation M1): the skip is status-blind."""
    filer.add_section(S1, filing_date=date(2023, 2, 1))
    scripted([_answer(_item("Examplar Widgets", Q_WIDGETS))])
    assert filer.read().proposed == 1
    [(row, acquired)] = filer.acquired_rows()

    headers, uid = _make_user(UserRole.ADMIN.value)
    try:
        db = SessionLocal()
        try:
            entity_graph.decide(db, relation_id=row.id, status="rejected", user=SimpleNamespace(id=uid))
        finally:
            db.close()

        scripted([_answer(_item("Examplar Widgets", Q_WIDGETS))])
        again = filer.read()
    finally:
        db = SessionLocal()
        try:
            db.query(EntityRelation).filter(EntityRelation.decided_by_id == uid).update(
                {"decided_by_id": None}, synchronize_session=False
            )
            db.commit()
        finally:
            db.close()
        _cleanup_user(uid)

    # The read was REACHED (the item came back and grounded) and then skipped.
    assert (again.items_returned, again.items_existing, again.proposed) == (1, 1, 0)
    [(row_after, acquired_after)] = filer.acquired_rows()
    assert (row_after.id, row_after.status, acquired_after.id) == (row.id, "rejected", acquired.id)


def test_never_merges_with_an_existing_entity_of_the_same_name(filer, scripted):
    db = SessionLocal()
    try:
        other = OrgEntity(id=uuid.uuid4(), legal_name="Examplar Widgets", cik=None)
        db.add(other)
        db.commit()
        filer.extra_entity_ids.append(other.id)
    finally:
        db.close()
    filer.add_section(S1, filing_date=date(2023, 2, 1))
    scripted([_answer(_item("Examplar Widgets", Q_WIDGETS))])

    assert filer.read().proposed == 1
    [(row, acquired)] = filer.acquired_rows()
    assert acquired.id != other.id and acquired.cik is None


def test_the_filer_itself_and_too_short_names_are_filtered(filer, scripted):
    text = S1 + f"{FILER_NAME} acquired AB Co in 2020.\n"
    filer.add_section(text, filing_date=date(2023, 2, 1))
    scripted([_answer(
        _item(FILER_NAME, f"{FILER_NAME} acquired AB Co in 2020."),
        _item("AB", f"{FILER_NAME} acquired AB Co in 2020."),
        _item("Examplar Widgets", Q_WIDGETS),
    )])

    result = filer.read()

    assert (result.items_filtered, result.proposed) == (2, 1)


def test_an_ungrounded_date_is_dropped_but_the_item_kept(filer, scripted):
    filer.add_section(S1, filing_date=date(2023, 2, 1))
    scripted([_answer(
        _item("Examplar Widgets", Q_WIDGETS, "June 2020"),        # not in the quote
        _item("Fictive Gadget Labs", Q_GADGETS, "August 2022,"),  # grounded, unparseable
    )])

    result = filer.read()

    assert (result.proposed, result.dates_dropped, result.dates_unparsed) == (2, 1, 1)
    for r, _ in filer.acquired_rows():
        assert (r.event_date, r.event_date_precision) == (None, "unknown")


@pytest.mark.parametrize("text,expected", [
    ("March 15, 2021", (date(2021, 3, 15), "day")),
    ("Sept. 3, 2019", (date(2019, 9, 3), "day")),
    ("August 2022", (date(2022, 8, 1), "month")),
    ("Dec. 2018", (date(2018, 12, 1), "month")),
    ("2023", (date(2023, 1, 1), "year")),
    ("February 30, 2021", (None, "unknown")),
    ("fiscal 2019", (None, "unknown")),
    ("the first quarter of 2020", (None, "unknown")),
    ("Smarch 2020", (None, "unknown")),
])
def test_parse_deal_date_is_strict(text, expected):
    assert ar.parse_deal_date(text) == expected


def test_a_long_section_is_cut_and_grounded_against_what_was_sent(filer, scripted, monkeypatch):
    monkeypatch.setattr(ar, "SECTION_CHAR_CAP", len("Note 3. Business Combinations\n") + len(Q_WIDGETS) + 1)
    filer.add_section(S1, filing_date=date(2023, 2, 1))
    t = scripted([_answer(_item("Examplar Widgets", Q_WIDGETS), _item("Fictive Gadget Labs", Q_GADGETS))])

    result = filer.read()

    assert _user_contents(t) == [S1[: ar.SECTION_CHAR_CAP]]
    # Fictive Gadget Labs IS in the stored section, but past the cut: the model
    # never saw it, so it cannot be grounded.
    assert (result.sections_truncated, result.proposed, result.items_ungrounded) == (1, 1, 1)


def test_a_section_the_model_cannot_structure_is_counted_and_the_run_continues(filer, scripted):
    filer.add_section(S1, filing_date=date(2023, 2, 1))
    filer.add_section(S2, filing_date=date(2024, 2, 1))
    bad = [_ok_response(content="not json") for _ in range(6)]  # 3 models x (tier 1 + tier 2)
    scripted(bad + [_answer(_item("Placeholder Sprockets", Q_SPROCKETS))])

    result = filer.read()

    assert (result.sections_failed, result.sections_read, result.proposed) == (1, 1, 1)


def test_budget_exhaustion_stops_the_run_and_keeps_earlier_proposals(filer, scripted):
    filer.add_section(S1, filing_date=date(2023, 2, 1))
    filer.add_section(S2, filing_date=date(2024, 2, 1))
    scripted([_answer(_item("Examplar Widgets", Q_WIDGETS)), _error_response(402, message="insufficient credits")])

    with pytest.raises(ar.AcquisitionReadStopped) as info:
        filer.read()

    assert info.value.result.stopped_by == "LLMBudgetExhausted"
    assert info.value.result.proposed == 1
    assert [e.legal_name for _, e in filer.acquired_rows()] == ["Examplar Widgets"]


def test_no_compliant_endpoint_stops_the_run(filer, scripted):
    filer.add_section(S1, filing_date=date(2023, 2, 1))
    scripted([_error_response(404, message="No endpoints found") for _ in range(3)])

    with pytest.raises(ar.AcquisitionReadStopped) as info:
        filer.read()

    assert info.value.result.stopped_by == "NoCompliantEndpoint"


def test_the_run_cost_sums_every_attempt_including_a_failed_one(filer, scripted):
    filer.add_section(S1, filing_date=date(2023, 2, 1))
    filer.add_section(S2, filing_date=date(2024, 2, 1))
    scripted([
        _ok_response(content="not json", cost=0.001),                   # tier 1, invalid
        _answer(_item("Examplar Widgets", Q_WIDGETS), cost=0.002),       # tier 2 repairs it
        _answer(_item("Placeholder Sprockets", Q_SPROCKETS), cost=0.004),
    ])

    result = filer.read()

    assert result.calls == 3
    assert result.cost_usd == pytest.approx(0.007)


def test_no_row_is_written_without_passing_the_per_item_check(filer, scripted, monkeypatch):
    filer.add_section(S1, filing_date=date(2023, 2, 1))
    scripted([_answer(_item("Examplar Widgets", Q_WIDGETS))])
    monkeypatch.setattr(ar, "check_grounding", lambda instance, span: ["forced"])

    result = filer.read()

    assert (result.items_ungrounded, result.proposed) == (1, 0)
    assert filer.acquired_rows() == []


def test_a_restricting_engagement_outranks_a_newer_closed_one(filer, scripted):
    db = SessionLocal()
    try:
        pre = make_engagement(db, "pre_close", subject_entity_id=filer.entity_id)
        day0 = make_engagement(
            db, "day_0", subject_entity_id=filer.entity_id, authorised_at=datetime.now(timezone.utc),
            authorisation_reference="aq218-test-authorisation",
        )
        day0.created_at = pre.created_at + timedelta(days=1)
        db.commit()
        filer.engagement_ids += [pre.id, day0.id]
        pre_id = pre.id
    finally:
        db.close()
    filer.add_section(S1, filing_date=date(2023, 2, 1))
    t = scripted([_answer(_item("Examplar Widgets", Q_WIDGETS))])

    result = filer.read()

    assert result.engagement_id == str(pre_id)
    db = SessionLocal()
    try:
        ledger = db.query(LlmCall).filter(LlmCall.task == ar.task_label(filer.run_ids[-1])).all()
    finally:
        db.close()
    assert [row.engagement_id for row in ledger] == [pre_id]
    # And the request went out under the strict policy.
    assert json.loads(t.requests[0].content)["provider"]["zdr"] is True


def test_newest_engagement_wins_among_equally_restrictive(filer):
    db = SessionLocal()
    try:
        older = make_engagement(db, "pre_close", subject_entity_id=filer.entity_id)
        newer = make_engagement(db, "pre_close", subject_entity_id=filer.entity_id)
        newer.created_at = older.created_at + timedelta(days=1)
        db.commit()
        filer.engagement_ids += [older.id, newer.id]
        assert ar.pick_engagement(db, filer.entity_id).id == newer.id
        assert ar.pick_engagement(db, uuid.uuid4()) is None
    finally:
        db.close()


# ── API ─────────────────────────────────────────────────────────────────────

@pytest.fixture
def admin():
    headers, uid = _make_user(UserRole.ADMIN.value)
    yield headers
    _cleanup_user(uid)


@pytest.fixture
def viewer():
    headers, uid = _make_user(UserRole.VIEWER.value)
    yield headers
    _cleanup_user(uid)


def test_api_run_succeeds_and_is_listed_under_the_entity_only(filer, scripted, admin, viewer):
    filer.add_section(S1, filing_date=date(2023, 2, 1))
    scripted([_answer(_item("Examplar Widgets", Q_WIDGETS, "March 15, 2021"))])

    resp = client.post(f"/api/entities/{filer.entity_id}/acquisition-read", headers=admin)
    assert resp.status_code == 202, resp.text
    run_id = resp.json()["id"]

    runs = client.get(f"/api/entities/{filer.entity_id}/acquisition-read/runs", headers=viewer).json()
    assert [(r["id"], r["kind"], r["status"]) for r in runs] == [(run_id, "acquisition_read", "succeeded")]
    assert runs[0]["result"]["proposed"] == 1
    assert runs[0]["result"]["calls"] == 1
    # The EDGAR ingest list does not show an AI read.
    ingest_ids = [r["id"] for r in client.get("/api/entities/edgar-ingest/runs?limit=100", headers=viewer).json()]
    assert run_id not in ingest_ids

    # The family table's source row carries the quote the reviewer decides on.
    edges = client.get(f"/api/entities/{filer.entity_id}/edges", headers=viewer).json()
    [source] = [s for e in edges for s in e["sources"] if s["observer"] == ar.OBSERVER]
    assert (source["quote"], source["grounding"], source["status"]) == (Q_WIDGETS, "verified", "proposed")


def test_api_stopped_run_records_the_error_and_the_counts(filer, scripted, admin):
    filer.add_section(S1, filing_date=date(2023, 2, 1))
    scripted([_error_response(402, message="insufficient credits")])

    run_id = client.post(f"/api/entities/{filer.entity_id}/acquisition-read", headers=admin).json()["id"]

    db = SessionLocal()
    try:
        run = db.get(EntityIngestRun, uuid.UUID(run_id))
        assert run.status == "failed"
        assert run.error.startswith("LLMBudgetExhausted")
        assert run.result["stopped_by"] == "LLMBudgetExhausted"
    finally:
        db.close()


def test_api_viewer_cannot_start_a_read(filer, viewer):
    filer.add_section(S1, filing_date=date(2023, 2, 1))
    assert client.post(f"/api/entities/{filer.entity_id}/acquisition-read", headers=viewer).status_code == 403


def test_api_unknown_entity_is_404(admin):
    assert client.post(f"/api/entities/{uuid.uuid4()}/acquisition-read", headers=admin).status_code == 404


def test_api_refuses_before_any_request_or_run_row(filer, scripted, admin):
    t = scripted([])
    # No stored section yet.
    resp = client.post(f"/api/entities/{filer.entity_id}/acquisition-read", headers=admin)
    assert resp.status_code == 409 and "no Business Combinations section" in resp.json()["detail"]

    # A section, but the connector disabled.
    filer.add_section(S1, filing_date=date(2023, 2, 1))
    db = SessionLocal()
    try:
        _configure_openrouter(db, enabled=False)
    finally:
        db.close()
    resp = client.post(f"/api/entities/{filer.entity_id}/acquisition-read", headers=admin)
    assert resp.status_code == 409 and "not configured" in resp.json()["detail"]

    assert t.requests == []
    db = SessionLocal()
    try:
        assert db.query(EntityIngestRun).filter(EntityIngestRun.cik == filer.cik).count() == 0
    finally:
        db.close()


def test_api_an_active_read_blocks_a_second_one(filer, openrouter, admin):
    filer.add_section(S1, filing_date=date(2023, 2, 1))
    db = SessionLocal()
    try:
        db.add(EntityIngestRun(cik=filer.cik, kind="acquisition_read", status="queued"))
        db.commit()
    finally:
        db.close()

    resp = client.post(f"/api/entities/{filer.entity_id}/acquisition-read", headers=admin)
    assert resp.status_code == 409 and "already queued or running" in resp.json()["detail"]


def test_one_active_run_per_kind_and_cik(filer):
    """Migration 0066's index: an AI read and an ingest of one filer may
    overlap; two of the same kind may not."""
    db = SessionLocal()
    try:
        db.add(EntityIngestRun(cik=filer.cik, kind="edgar_ingest", status="running", started_at=datetime.now(timezone.utc)))
        db.add(EntityIngestRun(cik=filer.cik, kind="acquisition_read", status="queued"))
        db.commit()
        db.add(EntityIngestRun(cik=filer.cik, kind="acquisition_read", status="queued"))
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()
        db.add(EntityIngestRun(cik=filer.cik, kind="something_else", status="queued"))
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()
    finally:
        db.close()


# ── planning#235: name variants, dedup keys, generic filter, dropped items ──

def test_legal_name_in_the_heading_short_name_in_the_sentence(filer, scripted):
    text = (
        "Note 5. Business Combinations\n"
        "Examplecorp, Inc.\n"
        "On June 1, 2024, the Company acquired all outstanding stock of Examplecorp, a leader in widget analytics.\n"
    )
    quote = "On June 1, 2024, the Company acquired all outstanding stock of Examplecorp, a leader in widget analytics."
    filer.add_section(text, filing_date=date(2024, 3, 1))
    scripted([_answer(_item("Examplecorp, Inc.", quote, "June 1, 2024"))])

    result = filer.read()

    assert (result.proposed, result.names_from_variant, result.dropped_items) == (1, 1, [])
    [(row, acquired)] = filer.acquired_rows()
    assert acquired.legal_name == "Examplecorp"
    assert row.grounding == "verified"
    assert (row.event_date, row.event_date_precision) == (date(2024, 6, 1), "day")


def test_defined_term_variant_is_stored(filer, scripted):
    text = (
        "Note 6. Business Combinations\n"
        "In 2023 the Company acquired Brightpath, a provider of routing software.\n"
    )
    quote = "In 2023 the Company acquired Brightpath, a provider of routing software."
    filer.add_section(text, filing_date=date(2023, 6, 1))
    scripted([_answer(_item("Holdco Nine, Inc. (“Brightpath”)", quote))])

    result = filer.read()

    assert result.proposed == 1
    [(_, acquired)] = filer.acquired_rows()
    assert acquired.legal_name == "Brightpath"


def test_invented_name_with_a_real_quote_is_dropped_as_name_not_in_quote(filer, scripted):
    filer.add_section(S1, filing_date=date(2023, 2, 1))
    scripted([_answer(_item("Invented Rival Corp", Q_WIDGETS))])

    result = filer.read()

    assert (result.items_returned, result.proposed) == (1, 0)
    assert result.dropped_items == [
        {"name": "Invented Rival Corp", "reason": "name_not_in_quote", "filing_date": "2023-02-01"}
    ]


def test_variant_must_be_a_whole_word_not_a_substring(filer, scripted):
    text = "Note 7. Business Combinations\nThe Company acquired Rotary Harvest Systems in 2022.\n"
    quote = "The Company acquired Rotary Harvest Systems in 2022."
    filer.add_section(text, filing_date=date(2022, 4, 1))
    scripted([_answer(_item("Rota, Inc.", quote))])

    result = filer.read()

    assert (result.items_returned, result.proposed) == (1, 0)
    assert result.dropped_items == [
        {"name": "Rota, Inc.", "reason": "name_not_in_quote", "filing_date": "2022-04-01"}
    ]


def test_a_stored_name_drops_its_trailing_defined_term(filer, scripted):
    text = (
        "Note 9. Business Combinations\n"
        "On May 3, 2022, the Company acquired Examplar Widgets, Inc. (“Examplar”), a maker of gears.\n"
    )
    quote = "On May 3, 2022, the Company acquired Examplar Widgets, Inc. (“Examplar”), a maker of gears."
    filer.add_section(text, filing_date=date(2022, 6, 1))
    scripted([_answer(_item("Examplar Widgets, Inc. (“Examplar”)", quote))])

    result = filer.read()

    assert (result.proposed, result.names_from_variant) == (1, 0)
    [(_, acquired)] = filer.acquired_rows()
    assert acquired.legal_name == "Examplar Widgets, Inc."


def test_variant_duplicates_across_three_10ks_collapse_to_one_row(filer, scripted):
    text_b = "Note 2. Business Combinations\nIn 2023, the Company noted its 2022 acquisition of CloudPeak LLC.\n"
    text_a = "Note 2. Business Combinations\nIn 2022, the Company acquired CloudPeak LLC (\"CloudPeak\"), a storage provider.\n"
    text_c = "Note 2. Business Combinations\nIn 2024, the Company referenced its acquisition of CloudPeak.\n"
    quote_a = "In 2022, the Company acquired CloudPeak LLC (\"CloudPeak\"), a storage provider."
    quote_b = "In 2023, the Company noted its 2022 acquisition of CloudPeak LLC."
    quote_c = "In 2024, the Company referenced its acquisition of CloudPeak."
    # Added out of filing-date order on purpose; the read still visits oldest first.
    filer.add_section(text_b, filing_date=date(2023, 2, 1))
    section_a = filer.add_section(text_a, filing_date=date(2022, 2, 1))
    filer.add_section(text_c, filing_date=date(2024, 2, 1))
    scripted([
        _answer(_item('CloudPeak LLC ("CloudPeak")', quote_a)),
        _answer(_item("CloudPeak LLC", quote_b)),
        _answer(_item("CloudPeak", quote_c)),
    ])

    result = filer.read()

    assert (result.items_returned, result.proposed, result.items_existing) == (3, 1, 2)
    rows = filer.acquired_rows()
    assert len(rows) == 1
    row, acquired = rows[0]
    assert acquired.legal_name == "CloudPeak LLC"
    assert row.evidence_id == section_a.evidence_id


def test_quote_alias_matches_the_name_from_a_later_filing(filer, scripted):
    text1 = (
        "Note 2. Business Combinations\n"
        "On July 21, 2021, the Company acquired all outstanding stock of Channelco Technologies, Inc. "
        "(“Channelco”), a messaging platform.\n"
    )
    quote1 = (
        "On July 21, 2021, the Company acquired all outstanding stock of Channelco Technologies, Inc. "
        "(“Channelco”), a messaging platform."
    )
    text2 = (
        "Note 3. Business Combinations\n"
        "On July 21, 2021, the Company acquired all outstanding stock of Channelco, a messaging platform.\n"
    )
    quote2 = "On July 21, 2021, the Company acquired all outstanding stock of Channelco, a messaging platform."
    filer.add_section(text1, filing_date=date(2021, 8, 15))
    filer.add_section(text2, filing_date=date(2022, 8, 15))
    scripted([
        _answer(_item("Channelco Technologies, Inc.", quote1)),
        _answer(_item("Channelco", quote2)),
    ])

    result = filer.read()

    assert (result.proposed, result.items_existing) == (1, 1)


def test_generic_defined_term_is_not_promoted_to_an_alias(filer, scripted):
    quote1 = "The Company acquired Alpha Widgets Inc. (the “Acquiree”) in 2021."
    quote2 = "The Company acquired Beta Gadgets Inc. (the “Acquiree”) in 2022."
    text = f"Note 4. Business Combinations\n{quote1}\n{quote2}\n"
    filer.add_section(text, filing_date=date(2023, 2, 1))
    scripted([_answer(_item("Alpha Widgets Inc.", quote1), _item("Beta Gadgets Inc.", quote2))])

    result = filer.read()

    assert result.proposed == 2
    assert {e.legal_name for _, e in filer.acquired_rows()} == {"Alpha Widgets Inc.", "Beta Gadgets Inc."}


def test_status_blind_skip_matches_the_normalised_key(filer, scripted):
    """planning#235 mutation M1: the normalised key, not byte-identity."""
    filer.add_section(S1, filing_date=date(2023, 2, 1))
    scripted([_answer(_item("Examplar Widgets", Q_WIDGETS))])
    assert filer.read().proposed == 1
    [(row, acquired)] = filer.acquired_rows()

    headers, uid = _make_user(UserRole.ADMIN.value)
    try:
        db = SessionLocal()
        try:
            entity_graph.decide(db, relation_id=row.id, status="rejected", user=SimpleNamespace(id=uid))
        finally:
            db.close()

        text2 = "Note 4. Acquisitions\nThe Company acquired Examplar Widgets, Inc. in 2024.\n"
        quote2 = "The Company acquired Examplar Widgets, Inc. in 2024."
        filer.add_section(text2, filing_date=date(2024, 2, 1))
        # S1 (2023) is read again first and returns nothing new; the later
        # section (2024) is the one carrying the re-spelled name.
        scripted([_answer(), _answer(_item("Examplar Widgets, Inc.", quote2))])
        again = filer.read()
    finally:
        db = SessionLocal()
        try:
            db.query(EntityRelation).filter(EntityRelation.decided_by_id == uid).update(
                {"decided_by_id": None}, synchronize_session=False
            )
            db.commit()
        finally:
            db.close()
        _cleanup_user(uid)

    assert (again.items_returned, again.items_existing, again.proposed) == (1, 1, 0)
    [(row_after, acquired_after)] = filer.acquired_rows()
    assert (row_after.id, row_after.status, acquired_after.id) == (row.id, "rejected", acquired.id)


def test_dedup_keys_never_cross_filers(filer, scripted):
    filer2 = _Filer()
    try:
        text2 = "Note 2. Business Combinations\nIn 2020, the Company acquired CloudPeak, a storage company.\n"
        quote2 = "In 2020, the Company acquired CloudPeak, a storage company."
        filer2.add_section(text2, filing_date=date(2020, 2, 1))
        scripted([_answer(_item("CloudPeak", quote2))])
        result2 = filer2.read()
        assert result2.proposed == 1
        [(_, acquired2)] = filer2.acquired_rows()

        text1 = "Note 2. Business Combinations\nIn 2021, the Company acquired CloudPeak LLC, a networking company.\n"
        quote1 = "In 2021, the Company acquired CloudPeak LLC, a networking company."
        filer.add_section(text1, filing_date=date(2021, 2, 1))
        scripted([_answer(_item("CloudPeak LLC", quote1))])
        result1 = filer.read()
        # REACHED and not skipped: another filer's key never suppresses this one.
        assert (result1.items_returned, result1.items_existing, result1.proposed) == (1, 0, 1)
        [(_, acquired1)] = filer.acquired_rows()

        assert acquired1.id != acquired2.id
    finally:
        filer2.close()


def test_generic_names_and_the_filer_itself_are_filtered_by_dedup_key(filer, scripted):
    q1 = "During the year, the Company acquired several companies including undisclosed local retailers."
    q2 = "In 2019, the Company acquired 13 companies across various regions."
    q3 = f"In 2020, the Company acquired {FILER_NAME}, Inc. assets."
    q4 = "In 2021, the Company acquired Fictive Companies, a logistics provider."
    text = "Note 6. Business Combinations\n" + "\n".join([q1, q2, q3, q4]) + "\n"
    filer.add_section(text, filing_date=date(2023, 2, 1))
    scripted([_answer(
        _item("several companies", q1),
        _item("13 companies", q2),
        _item(f"{FILER_NAME}, Inc.", q3),
        _item("Fictive Companies", q4),
    )])

    result = filer.read()

    assert (result.items_filtered, result.proposed) == (3, 1)
    assert {d["name"] for d in result.dropped_items} == {"several companies", "13 companies", f"{FILER_NAME}, Inc."}
    assert all(d["reason"] == "filtered" for d in result.dropped_items)
    assert [e.legal_name for _, e in filer.acquired_rows()] == ["Fictive Companies"]


def test_a_quote_not_in_the_section_is_dropped_and_recorded(filer, scripted):
    filer.add_section(S1, filing_date=date(2023, 2, 1))
    fake_quote = "This sentence never appears anywhere in the filing text."
    scripted([_answer(_item("Examplar Widgets", fake_quote))])

    result = filer.read()

    assert result.dropped_items == [
        {"name": "Examplar Widgets", "reason": "quote_not_in_text", "filing_date": "2023-02-01"}
    ]
    assert (result.items_ungrounded, result.proposed) == (1, 0)


def test_dropped_items_are_capped_and_long_names_truncated(filer, scripted, monkeypatch):
    monkeypatch.setattr(ar, "DROPPED_CAP", 2)
    filer.add_section(S1, filing_date=date(2023, 2, 1))
    long_name = ("Nonexistent Holdings " * 8).strip()
    assert len(long_name) > ar.DROPPED_NAME_CHARS
    scripted([_answer(
        _item(long_name, Q_WIDGETS),
        _item("Nonexistent Second Corp", Q_WIDGETS),
        _item("Nonexistent Third Corp", Q_GADGETS),
    )])

    result = filer.read()

    assert result.items_ungrounded == 3
    assert len(result.dropped_items) == 2
    assert result.dropped_items_omitted == 1
    assert result.dropped_items[0]["name"] == long_name[: ar.DROPPED_NAME_CHARS]
    assert len(result.dropped_items[0]["name"]) == ar.DROPPED_NAME_CHARS


def test_api_run_result_carries_dropped_items(filer, scripted, admin, viewer):
    filer.add_section(S1, filing_date=date(2023, 2, 1))
    scripted([_answer(
        _item("Examplar Widgets", Q_WIDGETS, "March 15, 2021"),
        _item("Ghost Rival Corp", Q_WIDGETS),
    )])

    resp = client.post(f"/api/entities/{filer.entity_id}/acquisition-read", headers=admin)
    assert resp.status_code == 202, resp.text
    run_id = resp.json()["id"]

    runs = client.get(f"/api/entities/{filer.entity_id}/acquisition-read/runs", headers=viewer).json()
    [run] = [r for r in runs if r["id"] == run_id]
    assert run["result"]["dropped_items"] == [
        {"name": "Ghost Rival Corp", "reason": "name_not_in_quote", "filing_date": "2023-02-01"}
    ]


@pytest.mark.parametrize("name,expected", [
    ('X, Inc. (“X”)', ("X, Inc.", "X")),
    ('2Alpha, Inc., (“Rypplet”)', ("2Alpha, Inc.", "Rypplet")),
    ("Plain Name", ("Plain Name", None)),
])
def test_split_defined_term_table(name, expected):
    assert ar.split_defined_term(name) == expected


@pytest.mark.parametrize("name,expected", [
    ("Examplecorp, Inc.", "Examplecorp"),
    ("Foo Pty Ltd", "Foo"),
    ("Northwind Data Company Ltd.", "Northwind Data Company"),
    ("Northwind Data Company", None),
    ("AB Co", None),
])
def test_strip_legal_suffix_table(name, expected):
    assert ar.strip_legal_suffix(name) == expected


@pytest.mark.parametrize("name,expected", [
    ("several companies", True),
    ("13 companies", True),
    ("the Company", True),
    ("two privately held companies", True),
    ("certain businesses", True),
    ("Acme Companies", False),
    ("Business Objects Labs", False),
    ("Target Corp", False),
])
def test_is_generic_table(name, expected):
    assert ar.is_generic(name) is expected


def test_dedup_key_ignores_defined_term_and_quote_style_and_spacing():
    keys = {
        ar.dedup_key('X Labs, Inc. (“X Labs”)'),
        ar.dedup_key('X Labs, Inc. ("X Labs")'),
        ar.dedup_key("x labs"),
        ar.dedup_key("X  Labs Inc."),
    }
    assert keys == {"x labs"}
