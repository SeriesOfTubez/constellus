"""EPSS score history (12-week rolling window).

Stores one row per (cve_id, calendar day) so we can surface score trend
charts and change indicators on the Finding detail view without storing
per-finding copies.  Sampled every 12h by the APScheduler job; the primary
key deduplicates to one row per CVE per day automatically.

Originally a TimescaleDB hypertable with an `add_retention_policy` call. Both
were removed so the chain runs on stock PostgreSQL with no extensions — the
84-day window is now enforced by `epss_history_service.prune_expired`, run
daily by the scheduler. The table is bounded and low-volume (one row per
tracked CVE per day), so a scheduled DELETE is sufficient; partitioning is
reserved for the high-volume history tables that come later.

Revision ID: 0033
Revises: 0032
Create Date: 2026-06-17
"""

from alembic import op
import sqlalchemy as sa


revision = "0033"
down_revision = "0032"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "epss_history",
        sa.Column("cve_id", sa.Text(), nullable=False),
        # stored as midnight UTC
        sa.Column("recorded_date", sa.DateTime(timezone=True), nullable=False),
        sa.Column("epss_score", sa.Float(), nullable=False),
        sa.Column("epss_percentile", sa.Float(), nullable=False),
        sa.PrimaryKeyConstraint("cve_id", "recorded_date"),
    )
    # Retention scan predicate — the PK leads with cve_id, so pruning by date
    # alone would otherwise be a sequential scan.
    op.create_index("ix_epss_history_recorded_date", "epss_history", ["recorded_date"])


def downgrade() -> None:
    op.drop_index("ix_epss_history_recorded_date", table_name="epss_history")
    op.drop_table("epss_history")
