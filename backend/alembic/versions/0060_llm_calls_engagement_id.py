"""Ledger rows carry the resolved engagement (planning#140 slice 2).

`llm_calls.engagement_id` snapshots the `Engagement`
`app.services.llm_connector._resolve_scope` resolved at call time — either
derived from the scoping target's `engagement_id`, or from an explicit
`engagement_id` argument when no `targets` row exists yet (the planning#215
research-loop case `_resolve_scope`'s own docstring cites). `ON DELETE SET
NULL`, unlike `targets.engagement_id`'s `RESTRICT` (0059): `targets.
engagement_id` already blocks an engagement's delete while any target still
links to it, so by the time an engagement CAN be deleted it has no member
targets left, and letting its historical `llm_calls` rows fall into the
unscoped (`NULL`) bucket rather than blocking the delete a second time is
accepted — see `app.models.llm_call.LlmCall.engagement_id`'s own comment.

## No backfill

This column is a SNAPSHOT of "which engagement was in scope when this
call was made", not "which engagement does this call's target belong to
today". Every `llm_calls` row that predates this migration was written
before `engagement_id` existed at all, by code that never recorded scope in
the first place — there is no earlier fact to recover. A target can also
move between engagements (or be detached and reattached) after a call was
made, so backfilling from the target's CURRENT `engagement_id` would not
reconstruct history; it would manufacture a data point — "this call was
scoped to engagement X" — that was never actually true at call time, under
a timestamp (`created_at`) that predates the fact being claimed. Every
pre-0060 row stays `NULL` (unscoped), which is the honest state: none of
them ever recorded scope.

Revision ID: 0060
Revises: 0059
Create Date: 2026-09-24
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "0060"
down_revision = "0059"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "llm_calls",
        sa.Column(
            "engagement_id",
            UUID(as_uuid=True),
            sa.ForeignKey("engagements.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("ix_llm_calls_engagement_id", "llm_calls", ["engagement_id"])


def downgrade() -> None:
    op.drop_index("ix_llm_calls_engagement_id", table_name="llm_calls")
    op.drop_column("llm_calls", "engagement_id")
