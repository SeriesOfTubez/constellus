"""EPSS score history hypertable (12-week rolling window).

Stores one row per (cve_id, calendar day) so we can surface score trend
charts and change indicators on the Finding detail view without storing
per-finding copies.  Sampled every 12h by the APScheduler job; the primary
key deduplicates to one row per CVE per day automatically.

84-day (12-week) TimescaleDB retention policy drops older chunks so the
table stays bounded without manual housekeeping.

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
        # stored as midnight UTC; TimescaleDB partitions on this column
        sa.Column("recorded_date", sa.DateTime(timezone=True), nullable=False),
        sa.Column("epss_score", sa.Float(), nullable=False),
        sa.Column("epss_percentile", sa.Float(), nullable=False),
        sa.PrimaryKeyConstraint("cve_id", "recorded_date"),
    )
    op.execute(
        "SELECT create_hypertable('epss_history', 'recorded_date', if_not_exists => TRUE)"
    )
    op.execute(
        "SELECT add_retention_policy('epss_history', INTERVAL '84 days', if_not_exists => TRUE)"
    )


def downgrade() -> None:
    op.execute(
        "SELECT remove_retention_policy('epss_history', if_not_exists => TRUE)"
    )
    op.drop_table("epss_history")
