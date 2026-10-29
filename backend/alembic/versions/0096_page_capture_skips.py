"""Page capture: record why the automatic sweep did not capture a candidate (planning#277 S6a).

`page_capture_skips` holds one row per candidate the weekly automatic sweep
refused or did not attempt, with the refusal rule (`archive:lookup_unavailable`,
`candidate:no_relationship`, `capture:sweep_stopped`, ...). It is a real table,
not a log line, so the candidate flyout can say why nothing was captured.
`candidate_id` is RESTRICT, like `page_captures`.

Data change: none; a new empty table.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0096"
down_revision = "0095"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "page_capture_skips",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("uuidv7()")),
        sa.Column(
            "candidate_id", postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scope_candidates.id", ondelete="RESTRICT"), nullable=False,
        ),
        sa.Column("domain", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("skipped_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.CheckConstraint("length(reason) > 0", name="ck_page_capture_skips_reason_nonempty"),
    )
    op.create_index(
        "ix_page_capture_skips_candidate_skipped", "page_capture_skips",
        ["candidate_id", sa.text("skipped_at DESC")],
    )


def downgrade() -> None:
    op.drop_index("ix_page_capture_skips_candidate_skipped", table_name="page_capture_skips")
    op.drop_table("page_capture_skips")
