"""AI acquisition reader — run `kind` + the `llm_acquisition_reader` observer
(planning#218).

## `entity_ingest_runs.kind`

planning#218's AI read of an entity's stored Business Combinations sections
is the same shape as #219's EDGAR ingest: an admin action on one filer, run
as a BackgroundTask, whose status the entity page polls. Rather than a
second table (and a second `run_reaper` path for its stranded rows), the run
record gains a `kind`:

  - `edgar_ingest`     — `POST /api/entities/edgar-ingest` (every existing
                         row, via the column default).
  - `acquisition_read` — `POST /api/entities/{id}/acquisition-read`.

The one-active-run guard moves from `cik` to `(kind, cik)`: an AI read may
run while an ingest of the same filer is running (it reads the sections
committed when it starts; a section stored later is read next time), but
two reads of one filer, or two ingests, still get a 409.

## The observer

`llm_acquisition_reader`: `trust='inferred'`, `confirms_relations=false`, so
every `acquired` row it asserts is PROPOSED and a person decides it (migration
0061's decision CHECK forbids an inferred observer from confirming no matter
what). `kind='connector'` like the EDGAR observers: it calls a third-party API
(the configured LLM provider, under `llm_connector`'s data policy).
`addressing='none'` and `noise_class='silent'`: it sends stored SEC text to
the LLM provider and never contacts the counterparty.

Revision ID: 0066
Revises: 0065
Create Date: 2026-09-26
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "0066"
down_revision = "0065"
branch_labels = None
depends_on = None

# Same literal as `app.services.acquisition_reader.OBSERVER` — not imported,
# for the reason 0062/0063 give: the migration must survive a later rename.
_OBSERVER = "llm_acquisition_reader"


def _observers_table():
    return sa.table(
        "observers",
        sa.column("id", UUID(as_uuid=True)),
        sa.column("name", sa.Text()),
        sa.column("kind", sa.Text()),
        sa.column("trust", sa.Text()),
        sa.column("addressing", sa.Text()),
        sa.column("noise_class", sa.Text()),
        sa.column("confirms_relations", sa.Boolean()),
        sa.column("description", sa.Text()),
    )


def _entity_relations_table():
    return sa.table(
        "entity_relations",
        sa.column("id", UUID(as_uuid=True)),
        sa.column("observer_id", UUID(as_uuid=True)),
    )


def upgrade() -> None:
    op.add_column(
        "entity_ingest_runs",
        sa.Column("kind", sa.Text(), nullable=False, server_default=sa.text("'edgar_ingest'")),
    )
    op.create_check_constraint(
        "ck_entity_ingest_runs_kind", "entity_ingest_runs", "kind IN ('edgar_ingest', 'acquisition_read')"
    )
    op.drop_index("uq_entity_ingest_runs_active_cik", table_name="entity_ingest_runs")
    op.create_index(
        "uq_entity_ingest_runs_active_kind_cik",
        "entity_ingest_runs",
        ["kind", "cik"],
        unique=True,
        postgresql_where=sa.text("status IN ('queued', 'running')"),
    )

    op.bulk_insert(
        _observers_table(),
        [
            {
                "name": _OBSERVER,
                "kind": "connector",
                "trust": "inferred",
                "addressing": "none",
                "noise_class": "silent",
                "confirms_relations": False,
                "description": (
                    "An LLM reads a filer's stored 10-K Business Combinations sections and "
                    "proposes the acquisitions they name. Each quote and name is checked "
                    "against the EXTRACTED section text (not the raw filing), which proves "
                    "the strings occur there, not that the deal happened. Sends stored SEC "
                    "text to the configured LLM provider under the data policy; never "
                    "contacts the counterparty. Proposals only."
                ),
            },
        ],
    )


def downgrade() -> None:
    conn = op.get_bind()
    observers = _observers_table()
    entity_relations = _entity_relations_table()
    observer_id = conn.execute(sa.select(observers.c.id).where(observers.c.name == _OBSERVER)).scalar()
    if observer_id is not None:
        # `acquired` rows asserted by this observer cannot outlive it.
        conn.execute(entity_relations.delete().where(entity_relations.c.observer_id == observer_id))
    conn.execute(observers.delete().where(observers.c.name == _OBSERVER))

    # A downgrade cannot keep AI-read runs: the old index is per CIK alone.
    conn.execute(sa.text("DELETE FROM entity_ingest_runs WHERE kind <> 'edgar_ingest'"))
    op.drop_index("uq_entity_ingest_runs_active_kind_cik", table_name="entity_ingest_runs")
    op.create_index(
        "uq_entity_ingest_runs_active_cik",
        "entity_ingest_runs",
        ["cik"],
        unique=True,
        postgresql_where=sa.text("status IN ('queued', 'running')"),
    )
    op.drop_constraint("ck_entity_ingest_runs_kind", "entity_ingest_runs", type_="check")
    op.drop_column("entity_ingest_runs", "kind")
