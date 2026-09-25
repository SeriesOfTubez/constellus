"""SEC EDGAR submissions ingest (planning#213, L4 slice 1).

Adds `entity_filing_events` — one row per 8-K (or 8-K/A) filing whose item
list intersects `edgar_ingest.LINEAGE_ITEMS` (2.01 "Completion of
Acquisition or Disposition of Assets", 5.01 "Change in Control of
Registrant"). This is an EVENT, never an `entity_relations` row: the
submissions JSON gives no counterparty, and item 2.01 covers both
directions (acquisition OR disposition), so there is no object entity and
no direction to assert. `items` is stored verbatim, exactly as SEC gave it.

## Two seeded observers, seeded HERE (the #198 lesson)

planning#198 burned this codebase once on seeding an observer's
classification before the code that IS it existed and behaves as claimed.
`edgar_former_names` and `edgar_8k_items` are seeded in this same migration
as the ingest module that is them (`app.services.edgar_ingest`), not
speculatively in 0061 alongside the schema that merely anticipated them
(see 0061's own docstring, "No observer rows seeded here").

`edgar_former_names` is the FIRST observer in the system granted
`confirms_relations = true`. It queries `data.sec.gov` (SEC's own dated
name-history record for a CIK), never the counterparty, so this is exactly
the `observed`-trust, non-`inferred` case `ck_observers_inferred_never_
confirms` (migration 0061) exists to allow. `edgar_8k_items` never confirms
— it writes `entity_filing_events`, not `entity_relations`, and
`confirms_relations` only ever governs the latter — so it is seeded
`false` for clarity, not because anything would otherwise let it confirm.

Both are `noise_class = 'silent'`: the query goes to the SEC, never to the
counterparty's own infrastructure, so `posture.PASSIVE_ONLY_PERMITTED_
NOISE` permits both even against a pre-close M&A target — see
`app.services.posture`'s own docstring for why `silent` is one of the two
noise classes a counterparty cannot notice at all.

## Downgrade order

`entity_filing_events` FKs onto `observers.id` (no ON DELETE clause — the
default is NO ACTION, matching the "no explicit ondelete" cells in the
table design below), so the table is dropped BEFORE the seeded observers
are deleted, not after. `entity_relations` rows asserted by
`edgar_former_names` cannot outlive their observer either (their composite
FK onto `(observers.id, observers.confirms_relations)`, migration 0061,
has no cascade), so those rows are deleted next, and only then the two
observer rows themselves.

Revision ID: 0062
Revises: 0061
Create Date: 2026-09-24
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "0062"
down_revision = "0061"
branch_labels = None
depends_on = None


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


# Names shared with `app.services.edgar_ingest`'s `OBSERVER_FORMER_NAMES` /
# `OBSERVER_8K_ITEMS` module constants. Not imported from there — a
# migration must keep working even if the module's constants are renamed
# later; the literal strings are the real seed.
_OBSERVER_FORMER_NAMES = "edgar_former_names"
_OBSERVER_8K_ITEMS = "edgar_8k_items"


def upgrade() -> None:
    op.create_table(
        "entity_filing_events",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column("entity_id", UUID(as_uuid=True), sa.ForeignKey("org_entities.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("observer_id", UUID(as_uuid=True), sa.ForeignKey("observers.id"), nullable=False),
        sa.Column("evidence_id", UUID(as_uuid=True), sa.ForeignKey("evidence_fetches.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("form", sa.Text(), nullable=False),
        sa.Column("accession_number", sa.Text(), nullable=False),
        sa.Column("filing_date", sa.Date(), nullable=False),
        # Verbatim SEC string (e.g. "2.01,7.01,9.01") — never normalised or
        # re-ordered by this schema or by the ingest that writes it.
        sa.Column("items", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "accession_number ~ '^[0-9]{10}-[0-9]{2}-[0-9]{6}$'",
            name="ck_entity_filing_events_accession",
        ),
        sa.UniqueConstraint("entity_id", "accession_number", name="uq_entity_filing_events_entity_accession"),
    )
    op.create_index("ix_entity_filing_events_entity_id", "entity_filing_events", ["entity_id"])

    # ── seed the two observers alongside the code that is them ─────────────
    observers = _observers_table()
    op.bulk_insert(
        observers,
        [
            {
                "name": _OBSERVER_FORMER_NAMES,
                "kind": "connector",
                "trust": "observed",
                "addressing": "none",
                "noise_class": "silent",
                "confirms_relations": True,
                "description": (
                    "SEC's own dated name history for a CIK, from data.sec.gov "
                    "submissions JSON; queries the SEC, never the counterparty."
                ),
            },
            {
                "name": _OBSERVER_8K_ITEMS,
                "kind": "connector",
                "trust": "observed",
                "addressing": "none",
                "noise_class": "silent",
                "confirms_relations": False,
                "description": (
                    "8-K item numbers for a CIK, recorded as filing events, "
                    "never relations; queries the SEC, never the counterparty."
                ),
            },
        ],
    )


def downgrade() -> None:
    op.drop_index("ix_entity_filing_events_entity_id", table_name="entity_filing_events")
    op.drop_table("entity_filing_events")

    conn = op.get_bind()
    observers = _observers_table()
    entity_relations = _entity_relations_table()

    former_names_id = conn.execute(
        sa.select(observers.c.id).where(observers.c.name == _OBSERVER_FORMER_NAMES)
    ).scalar()
    if former_names_id is not None:
        # `formerly_named` rows asserted by this observer cannot outlive it
        # (see module docstring) — delete them before the observer row.
        conn.execute(entity_relations.delete().where(entity_relations.c.observer_id == former_names_id))

    conn.execute(observers.delete().where(observers.c.name.in_([_OBSERVER_FORMER_NAMES, _OBSERVER_8K_ITEMS])))
