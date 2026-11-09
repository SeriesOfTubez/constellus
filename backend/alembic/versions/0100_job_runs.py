"""Record each run of a rolling scheduler job (planning#329).

`job_runs` holds one row per finished run of a recorded job (`capture_sweep`,
`rediscovery_tick` so far), written by the scheduler wrapper as its own unit
of work. It answers "did the job run at 14:40, for how long, over how many
items, and why did it stop?", which per-item stamps cannot.

- `finish_reason`: done | time_limit | lookup_failures | rate_limited |
  not_configured | error. `error` holds the exception TYPE only (the message
  can carry URLs or keys; the full error is in the logs), and is set exactly
  when the reason is `error`.
- `counts`: the job's own outcome names (the two jobs' outcome sets differ),
  a JSON object. `items_selected` is the one count every job has, as a column
  for sorting and filtering.
- A skipped run (backend down, previous run overran) writes no row by
  construction (`coalesce=True`, `max_instances=1`); gaps are computed at read
  time from the cadence in code.
- Retention: rolling, `jobs.run_history_days` (default 90).

Data change: none; a new empty table.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0100"
down_revision = "0099"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "job_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column("job", sa.Text(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finish_reason", sa.Text(), nullable=False),
        sa.Column("items_selected", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column(
            "counts", postgresql.JSONB(astext_type=sa.Text()), nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("error", sa.Text(), nullable=True),
        sa.CheckConstraint("length(job) > 0", name="ck_job_runs_job_nonempty"),
        sa.CheckConstraint("finished_at >= started_at", name="ck_job_runs_finished_after_started"),
        sa.CheckConstraint(
            "finish_reason IN ('done', 'time_limit', 'lookup_failures', 'rate_limited', 'not_configured', 'error')",
            name="ck_job_runs_finish_reason",
        ),
        sa.CheckConstraint("(finish_reason = 'error') = (error IS NOT NULL)", name="ck_job_runs_error_iff_reason"),
        sa.CheckConstraint("items_selected >= 0", name="ck_job_runs_items_selected_nonneg"),
        sa.CheckConstraint("jsonb_typeof(counts) = 'object'", name="ck_job_runs_counts_object"),
    )
    op.create_index("ix_job_runs_job_started", "job_runs", ["job", sa.text("started_at DESC")])
    op.create_index("ix_job_runs_started", "job_runs", ["started_at"])


def downgrade() -> None:
    op.drop_index("ix_job_runs_started", table_name="job_runs")
    op.drop_index("ix_job_runs_job_started", table_name="job_runs")
    op.drop_table("job_runs")
