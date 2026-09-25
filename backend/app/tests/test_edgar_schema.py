"""Schema/CHECK/constraint acceptance for SEC EDGAR ingest (planning#213,
L4 slice 1, migration 0062).

Follows `test_entity_graph_schema.py`'s convention: bypass
`app.services.edgar_ingest` entirely, drive `entity_filing_events` with raw
Core `INSERT`, and assert the `IntegrityError` itself — proving the service
never sends a bad row is not the same claim as proving the database refuses
one. Each CHECK/constraint test also proves its own happy path, so a
passing rejection test cannot be vacuous because the row never reached the
constraint it claims to (see this codebase's `feedback_vacuous_tests`
convention, and #212's own "a test titled for a CHECK was really hitting an
FK" lesson).

Run with:  backend/scripts/test.ps1 app/tests/test_edgar_schema.py
       or: pytest app/tests/test_edgar_schema.py
"""

import uuid
from datetime import date

from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from app.core.database import SessionLocal
from app.models.observer import Observer
from app.services.edgar_ingest import OBSERVER_8K_ITEMS, OBSERVER_FORMER_NAMES
from app.tests._entity_graph import cleanup_entity, cleanup_evidence, make_entity, make_evidence

# A static literal, every column named explicitly (see
# `test_entity_graph_schema.py`'s own comment on why this is exempt from
# semgrep's `avoid-sqlalchemy-text`: nothing here is assembled from a
# runtime-derived string, and every value is bound as a `:name` parameter).
_INSERT_FILING_EVENT_SQL = text(
    "INSERT INTO entity_filing_events "
    "(id, entity_id, observer_id, evidence_id, form, accession_number, filing_date, items) "
    "VALUES (:id, :entity_id, :observer_id, :evidence_id, :form, :accession_number, :filing_date, :items)"
)


def _insert_filing_event(db, **cols) -> uuid.UUID:
    row_id = cols.setdefault("id", uuid.uuid4())
    db.execute(_INSERT_FILING_EVENT_SQL, cols)
    return row_id


def _cleanup_filing_event(db, event_id: uuid.UUID | None) -> None:
    if event_id is None:
        return
    db.execute(text("DELETE FROM entity_filing_events WHERE id = :id"), {"id": event_id})


class _Rig:
    """One entity + one evidence fetch + the real seeded 8-K observer,
    reused across a test's several filing-event rows. Not a pytest fixture
    (matches `test_entity_graph_schema.py`'s `_Rig` convention: a plain
    class with its own `SessionLocal()`, so this file stays runnable as
    `python -m`)."""

    def __init__(self):
        self.db = SessionLocal()
        self.entity = make_entity(self.db, legal_name=f"Example Filing Rig {uuid.uuid4().hex[:6]}")
        self.evidence = make_evidence(
            self.db, source_url=f"https://data.sec.gov/edgar213-schema-{uuid.uuid4().hex[:8]}"
        )
        self.observer_id = self.db.execute(
            select(Observer.id).where(Observer.name == OBSERVER_8K_ITEMS)
        ).scalar_one()
        self.event_ids: list[uuid.UUID] = []

    def insert_event(self, **overrides) -> uuid.UUID:
        cols = dict(
            entity_id=self.entity.id,
            observer_id=self.observer_id,
            evidence_id=self.evidence.id,
            form="8-K",
            accession_number="9900000900-24-000900",
            filing_date=date(2024, 1, 1),
            items="2.01",
        )
        cols.update(overrides)
        eid = _insert_filing_event(self.db, **cols)
        self.event_ids.append(eid)
        return eid

    def close(self):
        self.db.rollback()
        for eid in self.event_ids:
            _cleanup_filing_event(self.db, eid)
        self.db.commit()
        cleanup_evidence(self.db, self.evidence.id)
        cleanup_entity(self.db, self.entity.id)
        self.db.close()


# ── 1. the accession CHECK ───────────────────────────────────────────────────

def test_accession_check_rejects_a_malformed_value():
    rig = _Rig()
    try:
        raised = False
        try:
            rig.insert_event(accession_number="not-a-valid-accession-number")
            rig.db.commit()
        except IntegrityError as exc:
            raised = True
            rig.db.rollback()
            assert "ck_entity_filing_events_accession" in str(exc)
        assert raised, "a malformed accession_number must be rejected by ck_entity_filing_events_accession"
    finally:
        rig.close()


def test_accession_check_allows_a_well_formed_value():
    """The happy path — proves the row above actually reached the CHECK
    rather than failing on an FK or a NOT NULL first."""
    rig = _Rig()
    try:
        rig.insert_event(accession_number="9900000901-24-000901")
        rig.db.commit()
        row = rig.db.execute(
            text("SELECT accession_number FROM entity_filing_events WHERE id = :id"), {"id": rig.event_ids[0]}
        ).scalar_one()
        assert row == "9900000901-24-000901"
    finally:
        rig.close()


# ── 2. UNIQUE (entity_id, accession_number) ─────────────────────────────────

def test_duplicate_entity_and_accession_is_refused_by_the_unique_constraint():
    rig = _Rig()
    try:
        rig.insert_event(accession_number="9900000902-24-000902")
        rig.db.commit()

        raised = False
        try:
            rig.insert_event(accession_number="9900000902-24-000902")
            rig.db.commit()
        except IntegrityError as exc:
            raised = True
            rig.db.rollback()
            assert "uq_entity_filing_events_entity_accession" in str(exc)
        assert raised, "a duplicate (entity_id, accession_number) must be refused by the unique constraint"
    finally:
        rig.close()


def test_same_accession_for_a_different_entity_is_allowed():
    """The happy path for the unique constraint's actual scope — it is
    (entity_id, accession_number), not accession_number alone."""
    rig_a = _Rig()
    rig_b = _Rig()
    try:
        rig_a.insert_event(accession_number="9900000903-24-000903")
        rig_a.db.commit()
        rig_b.insert_event(accession_number="9900000903-24-000903")
        rig_b.db.commit()
        assert len(rig_a.event_ids) == 1
        assert len(rig_b.event_ids) == 1
    finally:
        rig_a.close()
        rig_b.close()


# ── 3. the two seeded observers ──────────────────────────────────────────────

def test_both_seeded_observers_exist_with_the_spec_attributes():
    db = SessionLocal()
    try:
        rows = {
            o.name: o
            for o in db.query(Observer).filter(Observer.name.in_([OBSERVER_FORMER_NAMES, OBSERVER_8K_ITEMS])).all()
        }
        assert set(rows) == {OBSERVER_FORMER_NAMES, OBSERVER_8K_ITEMS}

        former_names = rows[OBSERVER_FORMER_NAMES]
        assert former_names.kind == "connector"
        assert former_names.trust == "observed"
        assert former_names.addressing == "none"
        assert former_names.noise_class == "silent"
        assert former_names.confirms_relations is True
        assert former_names.description.strip() != ""

        events = rows[OBSERVER_8K_ITEMS]
        assert events.kind == "connector"
        assert events.trust == "observed"
        assert events.addressing == "none"
        assert events.noise_class == "silent"
        assert events.confirms_relations is False
        assert events.description.strip() != ""
    finally:
        db.close()


def test_edgar_former_names_is_the_only_confirms_relations_true_observer():
    db = SessionLocal()
    try:
        granted = {name for (name,) in db.query(Observer.name).filter(Observer.confirms_relations.is_(True)).all()}
        assert granted == {OBSERVER_FORMER_NAMES}
    finally:
        db.close()
