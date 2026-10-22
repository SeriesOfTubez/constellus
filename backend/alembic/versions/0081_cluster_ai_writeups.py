"""Add `cluster_ai_writeups` (planning#233 slice 2b)

One row per AI write-up request for a cross-asset finding cluster, keyed by
the cluster identity `(finding_type, source, fingerprint)`: queued → running
→ succeeded | failed, the same lifecycle as `finding_ai_writeups` (0071).

`member_ids` freezes the finding ids the write-up described (ALL of them,
not only the members listed in the prompt). It is what the per-viewer read
gate checks: a write-up is shown only to a viewer who can read every frozen
member that still exists (planning#233, Jason 2026-10-22). `input_hash`
changes with membership, so a grown cluster reads "inputs changed".

A separate table on purpose: a per-finding key would misrepresent what was
written up, and AI output never lives on `findings_canonical`.

`uq_cluster_ai_writeups_active` lets at most one queued/running row exist
per cluster key, so two clicks (or a click and a scan) cannot pay twice.

New table only: no existing row changes.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0081"
down_revision = "0080"
branch_labels = None
depends_on = None

_STATUSES = ("queued", "running", "succeeded", "failed")
_KEY = ["finding_type", "source", "fingerprint"]


def upgrade() -> None:
    op.create_table(
        "cluster_ai_writeups",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column("finding_type", sa.Text(), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("fingerprint", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False, server_default=sa.text("'queued'")),
        sa.Column("member_ids", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("finding_count", sa.Integer(), nullable=True),
        sa.Column("asset_count", sa.Integer(), nullable=True),
        sa.Column("max_severity", sa.Text(), nullable=True),
        sa.Column("input_hash", sa.Text(), nullable=True),
        sa.Column("model", sa.Text(), nullable=True),
        sa.Column("ledger_ids", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("payload", postgresql.JSONB(), nullable=True),
        sa.Column("statements_returned", sa.Integer(), nullable=True),
        sa.Column("statements_dropped", sa.Integer(), nullable=True),
        sa.Column("summary_dropped", sa.Boolean(), nullable=True),
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
            " OR ".join(f"status = '{v}'" for v in _STATUSES), name="ck_cluster_ai_writeups_status",
        ),
    )
    op.create_index("ix_cluster_ai_writeups_key_created", "cluster_ai_writeups", [*_KEY, "created_at"])
    op.create_index(
        "uq_cluster_ai_writeups_active", "cluster_ai_writeups", _KEY, unique=True,
        postgresql_where=sa.text("status IN ('queued', 'running')"),
    )


def downgrade() -> None:
    op.drop_index("uq_cluster_ai_writeups_active", table_name="cluster_ai_writeups")
    op.drop_index("ix_cluster_ai_writeups_key_created", table_name="cluster_ai_writeups")
    op.drop_table("cluster_ai_writeups")
