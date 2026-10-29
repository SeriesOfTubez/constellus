"""Rolling re-discovery: per-unit "last refreshed" stamps (planning#277 S6b).

Each unit the hourly rolling job refreshes carries a time and a failed flag:
a claimed domain (`scope_candidates.rediscovered_at`: reverse-IP + RIR), an open
domain candidate (`reverified_at`: re-verified against the root's claimed
domains), and a root (`org_entities.rediscovered_at`: reassignment sweep +
dedicated-IP sweep). A unit is due when its time is NULL, or it failed more
than a day ago, or it was refreshed more than a week ago. A failed flag with no
time is meaningless, so a CHECK refuses it. The `scope_candidates_guard`
trigger (0087) freezes only identity and status, so stamping a claimed row is
allowed.

Data change: none; new nullable columns / false defaults.
"""

import sqlalchemy as sa
from alembic import op

revision = "0097"
down_revision = "0096"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scope_candidates", sa.Column("rediscovered_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "scope_candidates",
        sa.Column("rediscovery_failed", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("scope_candidates", sa.Column("reverified_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "scope_candidates",
        sa.Column("reverify_failed", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("org_entities", sa.Column("rediscovered_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "org_entities",
        sa.Column("rediscovery_failed", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_check_constraint(
        "ck_scope_candidates_rediscovery_failed_needs_time", "scope_candidates",
        "NOT rediscovery_failed OR rediscovered_at IS NOT NULL",
    )
    op.create_check_constraint(
        "ck_scope_candidates_reverify_failed_needs_time", "scope_candidates",
        "NOT reverify_failed OR reverified_at IS NOT NULL",
    )
    op.create_check_constraint(
        "ck_org_entities_rediscovery_failed_needs_time", "org_entities",
        "NOT rediscovery_failed OR rediscovered_at IS NOT NULL",
    )


def downgrade() -> None:
    op.drop_constraint("ck_org_entities_rediscovery_failed_needs_time", "org_entities", type_="check")
    op.drop_constraint("ck_scope_candidates_reverify_failed_needs_time", "scope_candidates", type_="check")
    op.drop_constraint("ck_scope_candidates_rediscovery_failed_needs_time", "scope_candidates", type_="check")
    op.drop_column("org_entities", "rediscovery_failed")
    op.drop_column("org_entities", "rediscovered_at")
    op.drop_column("scope_candidates", "reverify_failed")
    op.drop_column("scope_candidates", "reverified_at")
    op.drop_column("scope_candidates", "rediscovery_failed")
    op.drop_column("scope_candidates", "rediscovered_at")
