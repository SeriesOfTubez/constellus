"""Add `reports` (planning#230)

One row per generated report for an engagement: queued -> running -> done |
failed. `facts` holds the deterministic numbers (each with the query that
produced it, pinned to `as_of`); `payload` holds the AI narration kept after
per-statement grounding; `statements_dropped` / `drop_reasons` say what was
discarded and why.

`uq_reports_active` lets at most one queued/running report exist per
(engagement, kind), so two clicks cannot pay for two calls. The index on
`created_at` serves the retention purge.

New table only: no existing row changes.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0073"
down_revision = "0072"
branch_labels = None
depends_on = None

_STATUSES = ("queued", "running", "done", "failed")
_KINDS = ("exec_summary",)


def upgrade() -> None:
    op.create_table(
        "reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column(
            "engagement_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("kind", sa.String(40), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default=sa.text("'queued'")),
        sa.Column("prompt_version", sa.String(20), nullable=True),
        sa.Column("as_of", sa.DateTime(timezone=True), nullable=False),
        sa.Column("facts", postgresql.JSONB(), nullable=True),
        sa.Column("payload", postgresql.JSONB(), nullable=True),
        sa.Column("statements_returned", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("statements_dropped", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("drop_reasons", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("model", sa.String(), nullable=True),
        sa.Column("ledger_ids", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("forced_strict", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column(
            "requested_by_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(" OR ".join(f"kind = '{v}'" for v in _KINDS), name="ck_reports_kind"),
        sa.CheckConstraint(" OR ".join(f"status = '{v}'" for v in _STATUSES), name="ck_reports_status"),
    )
    op.create_index("ix_reports_engagement_id", "reports", ["engagement_id"])
    op.create_index("ix_reports_created_at", "reports", ["created_at"])
    op.create_index(
        "uq_reports_active", "reports", ["engagement_id", "kind"], unique=True,
        postgresql_where=sa.text("status IN ('queued', 'running')"),
    )


def downgrade() -> None:
    op.drop_index("uq_reports_active", table_name="reports")
    op.drop_index("ix_reports_created_at", table_name="reports")
    op.drop_index("ix_reports_engagement_id", table_name="reports")
    op.drop_table("reports")
