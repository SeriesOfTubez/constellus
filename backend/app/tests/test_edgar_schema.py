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
from app.services.edgar_ingest import OBSERVER_8K_ITEMS, OBSERVER_EX21, OBSERVER_FOOTNOTE, OBSERVER_FORMER_NAMES
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


# ═════════════════════════════════════════════════════════════════════════
# planning#213 slice 2, migration 0063: entity_subsidiary_listings +
# entity_filing_sections
# ═════════════════════════════════════════════════════════════════════════

_INSERT_SUBSIDIARY_LISTING_SQL = text(
    "INSERT INTO entity_subsidiary_listings "
    "(id, filer_entity_id, observer_id, evidence_id, accession_number, exhibit_type, "
    "filing_date, row_index, name, jurisdiction, cells, subsidiary_entity_id) "
    "VALUES (:id, :filer_entity_id, :observer_id, :evidence_id, :accession_number, :exhibit_type, "
    ":filing_date, :row_index, :name, :jurisdiction, :cells, :subsidiary_entity_id)"
)

_INSERT_FILING_SECTION_SQL = text(
    "INSERT INTO entity_filing_sections "
    "(id, entity_id, observer_id, evidence_id, accession_number, form, filing_date, section, "
    "extraction, heading, heading_match_count, start_line, end_line, text) "
    "VALUES (:id, :entity_id, :observer_id, :evidence_id, :accession_number, :form, :filing_date, :section, "
    ":extraction, :heading, :heading_match_count, :start_line, :end_line, :text)"
)


class _ListingRig:
    """One filer entity + a second (subsidiary) entity + one evidence fetch
    + the real seeded `edgar_ex21` observer, reused across a test's several
    `entity_subsidiary_listings` rows."""

    def __init__(self):
        self.db = SessionLocal()
        self.filer = make_entity(self.db, legal_name=f"Example Listing Filer {uuid.uuid4().hex[:6]}")
        self.subsidiary = make_entity(self.db, legal_name=f"Example Listing Sub {uuid.uuid4().hex[:6]}")
        self.evidence = make_evidence(
            self.db, source_url=f"https://www.sec.gov/edgar213b-schema-{uuid.uuid4().hex[:8]}"
        )
        self.observer_id = self.db.execute(select(Observer.id).where(Observer.name == OBSERVER_EX21)).scalar_one()
        self.row_ids: list[uuid.UUID] = []

    def insert_row(self, **overrides) -> uuid.UUID:
        cols = dict(
            id=uuid.uuid4(),
            filer_entity_id=self.filer.id,
            observer_id=self.observer_id,
            evidence_id=self.evidence.id,
            accession_number="9900000910-24-000910",
            exhibit_type="EX-21.1",
            filing_date=date(2024, 1, 1),
            row_index=0,
            name="Example Listing Sub",
            jurisdiction="Delaware",
            cells=["Example Listing Sub", "Delaware"],
            subsidiary_entity_id=self.subsidiary.id,
        )
        cols.update(overrides)
        self.db.execute(_INSERT_SUBSIDIARY_LISTING_SQL, cols)
        self.row_ids.append(cols["id"])
        return cols["id"]

    def close(self):
        self.db.rollback()
        for rid in self.row_ids:
            self.db.execute(text("DELETE FROM entity_subsidiary_listings WHERE id = :id"), {"id": rid})
        self.db.commit()
        cleanup_evidence(self.db, self.evidence.id)
        cleanup_entity(self.db, self.subsidiary.id)
        cleanup_entity(self.db, self.filer.id)
        self.db.close()


class _SectionRig:
    """One entity + one evidence fetch + the real seeded `edgar_10k_footnote`
    observer, reused across a test's `entity_filing_sections` rows."""

    def __init__(self):
        self.db = SessionLocal()
        self.entity = make_entity(self.db, legal_name=f"Example Section Filer {uuid.uuid4().hex[:6]}")
        self.evidence = make_evidence(
            self.db, source_url=f"https://www.sec.gov/edgar213b-section-schema-{uuid.uuid4().hex[:8]}"
        )
        self.observer_id = self.db.execute(select(Observer.id).where(Observer.name == OBSERVER_FOOTNOTE)).scalar_one()
        self.row_ids: list[uuid.UUID] = []

    def insert_row(self, **overrides) -> uuid.UUID:
        cols = dict(
            id=uuid.uuid4(),
            entity_id=self.entity.id,
            observer_id=self.observer_id,
            evidence_id=self.evidence.id,
            accession_number="9900000920-24-000920",
            form="10-K",
            filing_date=date(2024, 1, 1),
            section="business_combinations",
            extraction="last_heading_match_v1",
            heading="Note 4 - Business Combinations",
            heading_match_count=1,
            start_line=3,
            end_line=15,
            text="Note 4 - Business Combinations\nbody line",
        )
        cols.update(overrides)
        self.db.execute(_INSERT_FILING_SECTION_SQL, cols)
        self.row_ids.append(cols["id"])
        return cols["id"]

    def close(self):
        self.db.rollback()
        for rid in self.row_ids:
            self.db.execute(text("DELETE FROM entity_filing_sections WHERE id = :id"), {"id": rid})
        self.db.commit()
        cleanup_evidence(self.db, self.evidence.id)
        cleanup_entity(self.db, self.entity.id)
        self.db.close()


# ── entity_subsidiary_listings: accession CHECK ──────────────────────────────

def test_subsidiary_listing_accession_check_rejects_a_malformed_value():
    rig = _ListingRig()
    try:
        raised = False
        try:
            rig.insert_row(accession_number="not-a-valid-accession-number")
            rig.db.commit()
        except IntegrityError as exc:
            raised = True
            rig.db.rollback()
            assert "ck_entity_subsidiary_listings_accession" in str(exc)
        assert raised, "a malformed accession_number must be rejected"
    finally:
        rig.close()


def test_subsidiary_listing_accession_check_allows_a_well_formed_value():
    rig = _ListingRig()
    try:
        rig.insert_row(accession_number="9900000911-24-000911")
        rig.db.commit()
        row = rig.db.execute(
            text("SELECT accession_number FROM entity_subsidiary_listings WHERE id = :id"), {"id": rig.row_ids[0]}
        ).scalar_one()
        assert row == "9900000911-24-000911"
    finally:
        rig.close()


# ── entity_subsidiary_listings: UNIQUE (filer, accession, exhibit, row) ─────

def test_subsidiary_listing_unique_key_rejects_a_duplicate_tuple():
    rig = _ListingRig()
    try:
        rig.insert_row(accession_number="9900000912-24-000912", row_index=0)
        rig.db.commit()

        raised = False
        try:
            rig.insert_row(accession_number="9900000912-24-000912", row_index=0)
            rig.db.commit()
        except IntegrityError as exc:
            raised = True
            rig.db.rollback()
            assert "uq_entity_subsidiary_listings_filer_accession_exhibit_row" in str(exc)
        assert raised, "a duplicate (filer, accession, exhibit_type, row_index) must be refused"
    finally:
        rig.close()


def test_subsidiary_listing_unique_key_allows_a_different_row_index():
    """The happy path for the unique key's actual scope — a second row for
    the SAME (filer, accession, exhibit_type) but a different `row_index`
    is exactly what a multi-row EX-21 exhibit looks like."""
    rig = _ListingRig()
    try:
        rig.insert_row(accession_number="9900000913-24-000913", row_index=0)
        rig.db.commit()
        rig.insert_row(accession_number="9900000913-24-000913", row_index=1, name="Example Listing Sub Two")
        rig.db.commit()
        assert len(rig.row_ids) == 2
    finally:
        rig.close()


# ── entity_filing_sections: section CHECK ────────────────────────────────────

def test_filing_section_check_rejects_a_value_outside_the_vocabulary():
    rig = _SectionRig()
    try:
        raised = False
        try:
            rig.insert_row(section="goodwill")
            rig.db.commit()
        except IntegrityError as exc:
            raised = True
            rig.db.rollback()
            assert "ck_entity_filing_sections_section" in str(exc)
        assert raised, "a section outside {'business_combinations'} must be rejected"
    finally:
        rig.close()


def test_filing_section_check_allows_business_combinations():
    rig = _SectionRig()
    try:
        rig.insert_row(section="business_combinations")
        rig.db.commit()
        row = rig.db.execute(
            text("SELECT section FROM entity_filing_sections WHERE id = :id"), {"id": rig.row_ids[0]}
        ).scalar_one()
        assert row == "business_combinations"
    finally:
        rig.close()


# ── entity_filing_sections: end_line > start_line CHECK ─────────────────────

def test_filing_section_end_after_start_check_rejects_end_not_after_start():
    rig = _SectionRig()
    try:
        raised = False
        try:
            rig.insert_row(accession_number="9900000921-24-000921", start_line=10, end_line=10)
            rig.db.commit()
        except IntegrityError as exc:
            raised = True
            rig.db.rollback()
            assert "ck_entity_filing_sections_end_after_start" in str(exc)
        assert raised, "end_line must be strictly greater than start_line"
    finally:
        rig.close()


def test_filing_section_end_after_start_check_allows_end_after_start():
    rig = _SectionRig()
    try:
        rig.insert_row(accession_number="9900000922-24-000922", start_line=3, end_line=4)
        rig.db.commit()
        row = rig.db.execute(
            text("SELECT start_line, end_line FROM entity_filing_sections WHERE id = :id"), {"id": rig.row_ids[0]}
        ).one()
        assert tuple(row) == (3, 4)
    finally:
        rig.close()


# ── entity_filing_sections: UNIQUE (entity, accession, section) ────────────

def test_filing_section_unique_key_rejects_a_duplicate_tuple():
    rig = _SectionRig()
    try:
        rig.insert_row(accession_number="9900000923-24-000923")
        rig.db.commit()

        raised = False
        try:
            rig.insert_row(accession_number="9900000923-24-000923")
            rig.db.commit()
        except IntegrityError as exc:
            raised = True
            rig.db.rollback()
            assert "uq_entity_filing_sections_entity_accession_section" in str(exc)
        assert raised, "a duplicate (entity_id, accession_number, section) must be refused"
    finally:
        rig.close()


def test_filing_section_unique_key_allows_a_different_accession():
    """The happy path for the unique key's actual scope — the SAME entity
    and section, a DIFFERENT accession (a later year's 10-K), is exactly
    what one filer's multi-year section history looks like."""
    rig = _SectionRig()
    try:
        rig.insert_row(accession_number="9900000924-24-000924")
        rig.db.commit()
        rig.insert_row(accession_number="9900000925-24-000925")
        rig.db.commit()
        assert len(rig.row_ids) == 2
    finally:
        rig.close()


# ── the two seeded slice-2 observers ─────────────────────────────────────────

def test_both_slice2_observers_exist_with_the_spec_attributes():
    db = SessionLocal()
    try:
        rows = {
            o.name: o for o in db.query(Observer).filter(Observer.name.in_([OBSERVER_EX21, OBSERVER_FOOTNOTE])).all()
        }
        assert set(rows) == {OBSERVER_EX21, OBSERVER_FOOTNOTE}

        for name in (OBSERVER_EX21, OBSERVER_FOOTNOTE):
            row = rows[name]
            assert row.kind == "connector"
            assert row.trust == "observed"
            assert row.addressing == "none"
            assert row.noise_class == "silent"
            assert row.confirms_relations is False
            assert row.description.strip() != ""
    finally:
        db.close()


def test_edgar_former_names_is_still_the_only_confirms_relations_true_observer_after_slice2():
    """Re-asserts slice 1's invariant now that TWO more observers exist —
    neither `edgar_ex21` nor `edgar_10k_footnote` is granted."""
    db = SessionLocal()
    try:
        granted = {name for (name,) in db.query(Observer.name).filter(Observer.confirms_relations.is_(True)).all()}
        assert granted == {OBSERVER_FORMER_NAMES}
    finally:
        db.close()
