"""Add `finding_ai_writeups` (planning#226)

One row per AI write-up request for a finding: queued → running →
succeeded | failed. A succeeded row holds the write-up (`payload`), the
hash of the exact input that produced it (`input_hash`, the cache key), the
model that served it, and the `llm_calls` ledger ids behind it. Regenerate
adds a row; the newest succeeded row is the one shown.

A separate table on purpose: AI output never lives on `findings_canonical`,
whose columns scoring, SSVC and hygiene read.

`uq_finding_ai_writeups_active` lets at most one queued/running row exist
per finding, so two clicks cannot pay for two calls.

New table only: no existing row changes.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0071"
down_revision = "0070"
branch_labels = None
depends_on = None

_STATUSES = ("queued", "running", "succeeded", "failed")


def upgrade() -> None:
    op.create_table(
        "finding_ai_writeups",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column(
            "finding_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("findings_canonical.id", ondelete="CASCADE"), nullable=False,
        ),
        sa.Column("status", sa.Text(), nullable=False, server_default=sa.text("'queued'")),
        sa.Column("input_hash", sa.Text(), nullable=True),
        sa.Column("model", sa.Text(), nullable=True),
        sa.Column("ledger_ids", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("payload", postgresql.JSONB(), nullable=True),
        sa.Column("statements_returned", sa.Integer(), nullable=True),
        sa.Column("statements_dropped", sa.Integer(), nullable=True),
        sa.Column("priority_note_dropped", sa.Boolean(), nullable=True),
        sa.Column("forced_strict", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column(
            "requested_by_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            " OR ".join(f"status = '{v}'" for v in _STATUSES), name="ck_finding_ai_writeups_status",
        ),
    )
    op.create_index("ix_finding_ai_writeups_finding_created", "finding_ai_writeups", ["finding_id", "created_at"])
    op.create_index(
        "uq_finding_ai_writeups_active", "finding_ai_writeups", ["finding_id"], unique=True,
        postgresql_where=sa.text("status IN ('queued', 'running')"),
    )


def downgrade() -> None:
    op.drop_index("uq_finding_ai_writeups_active", table_name="finding_ai_writeups")
    op.drop_index("ix_finding_ai_writeups_finding_created", table_name="finding_ai_writeups")
    op.drop_table("finding_ai_writeups")
