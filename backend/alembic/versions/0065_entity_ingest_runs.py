"""entity_ingest_runs — a status record for each EDGAR ingest request
(planning#219, the entity page's "Map a company" action).

`POST /api/entities/edgar-ingest` was fire-and-forget: 202 plus a
`BackgroundTasks` call, with failures landing only in `system_logs`. The
entity itself is created MID-run (after the submissions fetch), so the
person who asked could not even tell whether anything had happened. One
row per request answers "is it still running, did it work, and if not, why".

## No `entity_id` column

`org_entities.cik` is unique and an ingest never renames or re-keys an
entity, so the run's entity is resolved from its CIK at READ time. That
also makes the link available while the run is still going, as soon as
the entity upsert commits, which a column written at the end would not.

## One active run per CIK — `uq_entity_ingest_runs_active_cik`

A partial unique index over `cik WHERE status IN ('queued', 'running')`.
Two concurrent ingests of one filer would race each other's upserts; the
index turns the second request into a 409 instead, and it holds under
concurrent POSTs, which an application-level "is one running?" check
does not. A run stranded by a backend restart would hold the index
forever, so `run_reaper` fails unfinished rows at startup and by age.

## `status` ⇔ timestamps / outcome

  - `finished_at` is set iff the run is `succeeded` or `failed`.
  - `started_at` is set for every status except `queued`.
  - a `failed` row carries an `error`; a `succeeded` row carries `result`
    (the `IngestResult` counts, including which observers were `denied`).

`requested_by_id` is SET NULL and outside every CHECK, same reasoning as
`candidate_domains.decided_by_id` (0064).

Revision ID: 0065
Revises: 0064
Create Date: 2026-09-26
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0065"
down_revision = "0064"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "entity_ingest_runs",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column("cik", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False, server_default=sa.text("'queued'")),
        sa.Column("result", JSONB(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("requested_by_id", UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("cik ~ '^[0-9]{10}$'", name="ck_entity_ingest_runs_cik"),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'succeeded', 'failed')", name="ck_entity_ingest_runs_status"
        ),
        sa.CheckConstraint(
            "(status IN ('succeeded', 'failed')) = (finished_at IS NOT NULL)", name="ck_entity_ingest_runs_finished"
        ),
        sa.CheckConstraint(
            "(status = 'queued') = (started_at IS NULL)", name="ck_entity_ingest_runs_started"
        ),
        sa.CheckConstraint("status <> 'failed' OR error IS NOT NULL", name="ck_entity_ingest_runs_error"),
        sa.CheckConstraint("status <> 'succeeded' OR result IS NOT NULL", name="ck_entity_ingest_runs_result"),
    )
    op.create_index("ix_entity_ingest_runs_created_at", "entity_ingest_runs", ["created_at"])
    op.create_index(
        "uq_entity_ingest_runs_active_cik",
        "entity_ingest_runs",
        ["cik"],
        unique=True,
        postgresql_where=sa.text("status IN ('queued', 'running')"),
    )


def downgrade() -> None:
    op.drop_index("uq_entity_ingest_runs_active_cik", table_name="entity_ingest_runs")
    op.drop_index("ix_entity_ingest_runs_created_at", table_name="entity_ingest_runs")
    op.drop_table("entity_ingest_runs")
