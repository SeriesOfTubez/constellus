"""EX-21 subsidiary listings + 10-K Business Combinations sections
(planning#213, L4 slice 2).

Two new tables, both DATA, neither an `entity_relations` row by itself:

  - `entity_subsidiary_listings` — one row per KEPT (non-heading,
    non-self) row of one 10-K's EX-21 exhibit, stored VERBATIM. This is a
    snapshot, not a diff: the year-over-year delta a person wants is a
    query over these rows (grouped by `filer_entity_id`, ordered by
    `filing_date`), never a stored computation. Exactly ONE
    `subsidiary_of` `entity_relations` row is proposed per distinct
    (filer, exact name, exact jurisdiction) at its FIRST appearance —
    written by `app.services.edgar_ingest`, through `entity_graph.
    assert_relation` like every other relation in this system, never a raw
    insert here.
  - `entity_filing_sections` — one row per located "Business Combinations"
    (or "Acquisitions") footnote in a 10-K, located by "take the LAST
    heading match" (the research method's rule — the FIRST match is
    usually the table of contents). No relation is ever written from this
    table; naming the deal is planning#215's job, over the stored `text`
    and offsets here.

## Both new observers are ungranted (`confirms_relations = false`)

Unlike migration 0062's `edgar_former_names` (SEC's own dated name
history — a fact, not a guess), an EX-21 row's mapping onto an EXISTING
vs. NEW `org_entities` row, and a footnote's heading-match locate, are
both heuristic parses. A new EX-21 row may be an acquisition OR a newly
formed subsidiary (planning#213's 2026-09-25 decisions comment); nothing
here is auto-confirmed, and nothing is labelled `acquired`. `edgar_ex21`
being ungranted also means `assert_relation` never sets `status`/
`decision_kind` for this observer's rows: every `subsidiary_of` row it
writes lands `status='proposed'`, and a person decides.

## Why `entity_subsidiary_listings` is not just a wider `entity_relations`
   row

A listing row carries no `object_id` — the object of a `subsidiary_of`
relation is an `org_entities` row (`subsidiary_entity_id`, set at ingest
time via the scoped-exact-reuse rule in `app.services.edgar_ingest`'s
module docstring), but the LISTING itself is filer-scoped inventory data:
"this filer's EX-21 said this on this date", independent of whether a
relation was ever proposed for it (a heading row, or a row matching the
filer's own current name, is stored in no table at all — see
`edgar_ingest._is_heading_row`). Mixing that into `entity_relations` would
force every heading/self row to either become a nonsensical relation or be
silently dropped with no record it was ever seen.

## `entity_filing_sections.text` is extraction, not fact

The module docstring in `app.services.edgar_ingest` (§5's limitation,
carried into the extraction code itself) states plainly: the LAST
heading-match rule can land on a later, unrelated mention (e.g. a
subsequent-events note also titled "Acquisitions"). `heading_match_count`
is stored specifically so a reader — a person, or planning#215's AI
research loop — can see that ambiguity rather than trusting a single
number silently.

## Downgrade order

`entity_subsidiary_listings` FKs onto `org_entities` twice
(`filer_entity_id`, `subsidiary_entity_id`, both RESTRICT) and onto
`evidence_fetches`/`observers`; `entity_filing_sections` FKs onto
`org_entities`/`evidence_fetches`/`observers`. Both tables are dropped
before the two new observers are deleted (same reasoning as 0062:
`entity_relations` rows asserted by `edgar_ex21` cannot outlive their
observer, and neither table's own FK onto `observers.id` has a cascade).

Revision ID: 0063
Revises: 0062
Create Date: 2026-09-25
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import ARRAY, UUID

revision = "0063"
down_revision = "0062"
branch_labels = None
depends_on = None


# Same CHECK regex as 0062's `ck_entity_filing_events_accession`, given its
# own constraint name per table (per the spec: "own constraint name").
_ACCESSION_REGEX = "^[0-9]{10}-[0-9]{2}-[0-9]{6}$"


def _observers_table():
    return sa.table(
        "observers",
        sa.column("id", UUID(as_uuid=True)),
        sa.column("name", sa.Text()),
        sa.column("kind", sa.Text()),
        sa.column("trust", sa.Text()),
        sa.column("addressing", sa.Text()),
        sa.column("noise_class", sa.Text()),
        sa.column("description", sa.Text()),
        sa.column("confirms_relations", sa.Boolean()),
    )


def _entity_relations_table():
    return sa.table(
        "entity_relations",
        sa.column("id", UUID(as_uuid=True)),
        sa.column("observer_id", UUID(as_uuid=True)),
    )


# Names shared with `app.services.edgar_ingest`'s `OBSERVER_EX21` /
# `OBSERVER_FOOTNOTE` module constants. Not imported from there — same
# reasoning as 0062: a migration must keep working even if the module's
# constants are renamed later; the literal strings are the real seed.
_OBSERVER_EX21 = "edgar_ex21"
_OBSERVER_FOOTNOTE = "edgar_10k_footnote"


def upgrade() -> None:
    # ── entity_subsidiary_listings ──────────────────────────────────────────
    op.create_table(
        "entity_subsidiary_listings",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column("filer_entity_id", UUID(as_uuid=True), sa.ForeignKey("org_entities.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("observer_id", UUID(as_uuid=True), sa.ForeignKey("observers.id"), nullable=False),
        sa.Column("evidence_id", UUID(as_uuid=True), sa.ForeignKey("evidence_fetches.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("accession_number", sa.Text(), nullable=False),
        # Verbatim index `Type` cell, e.g. "EX-21.1" — never normalised.
        sa.Column("exhibit_type", sa.Text(), nullable=False),
        sa.Column("filing_date", sa.Date(), nullable=False),
        # The 10-K's reportDate (period end), when SEC gives one.
        sa.Column("report_date", sa.Date(), nullable=True),
        # 0-based position among KEPT (non-heading, non-self) rows for this
        # (filer, accession, exhibit_type) — see app.services.edgar_ingest.
        sa.Column("row_index", sa.Integer(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("jurisdiction", sa.Text(), nullable=True),
        # Every non-empty cell, normalised (whitespace/NBSP collapsed,
        # html.unescape'd) — the verbatim-as-text row.
        sa.Column("cells", ARRAY(sa.Text()), nullable=False),
        sa.Column("subsidiary_entity_id", UUID(as_uuid=True), sa.ForeignKey("org_entities.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(f"accession_number ~ '{_ACCESSION_REGEX}'", name="ck_entity_subsidiary_listings_accession"),
        sa.UniqueConstraint(
            "filer_entity_id", "accession_number", "exhibit_type", "row_index",
            name="uq_entity_subsidiary_listings_filer_accession_exhibit_row",
        ),
    )
    op.create_index(
        "ix_entity_subsidiary_listings_filer_name", "entity_subsidiary_listings", ["filer_entity_id", "name"],
    )

    # ── entity_filing_sections ───────────────────────────────────────────────
    op.create_table(
        "entity_filing_sections",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column("entity_id", UUID(as_uuid=True), sa.ForeignKey("org_entities.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("observer_id", UUID(as_uuid=True), sa.ForeignKey("observers.id"), nullable=False),
        sa.Column("evidence_id", UUID(as_uuid=True), sa.ForeignKey("evidence_fetches.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("accession_number", sa.Text(), nullable=False),
        sa.Column("form", sa.Text(), nullable=False),
        sa.Column("filing_date", sa.Date(), nullable=False),
        sa.Column("report_date", sa.Date(), nullable=True),
        sa.Column("section", sa.Text(), nullable=False),
        # The method id, e.g. "last_heading_match_v1" — versioned so a
        # future extraction method change never gets confused with this
        # one's known limitation (module docstring, `app.services.
        # edgar_ingest`: the LAST match can land on a later, unrelated
        # mention).
        sa.Column("extraction", sa.Text(), nullable=False),
        sa.Column("heading", sa.Text(), nullable=False),
        sa.Column("heading_match_count", sa.Integer(), nullable=False),
        sa.Column("start_line", sa.Integer(), nullable=False),
        sa.Column("end_line", sa.Integer(), nullable=False),
        sa.Column("text", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(f"accession_number ~ '{_ACCESSION_REGEX}'", name="ck_entity_filing_sections_accession"),
        sa.CheckConstraint("section IN ('business_combinations')", name="ck_entity_filing_sections_section"),
        sa.CheckConstraint("end_line > start_line", name="ck_entity_filing_sections_end_after_start"),
        sa.UniqueConstraint("entity_id", "accession_number", "section", name="uq_entity_filing_sections_entity_accession_section"),
    )

    # ── seed the two new observers, ungranted ───────────────────────────────
    observers = _observers_table()
    op.bulk_insert(
        observers,
        [
            {
                "name": _OBSERVER_EX21,
                "kind": "connector",
                "trust": "observed",
                "addressing": "none",
                "noise_class": "silent",
                "confirms_relations": False,
                "description": (
                    "SEC EX-21 subsidiary-listing exhibit for a CIK's 10-K filings, "
                    "from www.sec.gov; queries the SEC, never the counterparty. A new "
                    "row may be an acquisition or a newly formed subsidiary, so "
                    "nothing here is auto-confirmed."
                ),
            },
            {
                "name": _OBSERVER_FOOTNOTE,
                "kind": "connector",
                "trust": "observed",
                "addressing": "none",
                "noise_class": "silent",
                "confirms_relations": False,
                "description": (
                    "Locates a 10-K's Business Combinations (or Acquisitions) "
                    "footnote by heading match and stores the section text for a "
                    "later reader; writes no relations. Queries the SEC, never the "
                    "counterparty."
                ),
            },
        ],
    )


def downgrade() -> None:
    op.drop_index("ix_entity_subsidiary_listings_filer_name", table_name="entity_subsidiary_listings")
    op.drop_table("entity_filing_sections")
    op.drop_table("entity_subsidiary_listings")

    conn = op.get_bind()
    observers = _observers_table()
    entity_relations = _entity_relations_table()

    ex21_id = conn.execute(sa.select(observers.c.id).where(observers.c.name == _OBSERVER_EX21)).scalar()
    if ex21_id is not None:
        # `subsidiary_of` rows asserted by this observer cannot outlive it.
        conn.execute(entity_relations.delete().where(entity_relations.c.observer_id == ex21_id))

    conn.execute(observers.delete().where(observers.c.name.in_([_OBSERVER_EX21, _OBSERVER_FOOTNOTE])))
