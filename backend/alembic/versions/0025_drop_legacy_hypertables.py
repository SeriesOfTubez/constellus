"""Drop the legacy assets and findings hypertables

The continuous-monitoring rebuild moved durable identity onto
assets_canonical and findings_canonical. The transitional hypertables
were dual-written so legacy readers kept working during the migration;
all readers have now moved over.

Per-scan counts (asset_count / finding_count) used to be derived from
the hypertables via scan_run_id filters. Those counts now live on
scan_runs itself, populated by the executor at run completion.

This migration:
  1. Adds asset_count + finding_count columns to scan_runs.
  2. Backfills them from the hypertables (best effort) before drop.
  3. Drops findings and assets along with their associated indexes.

Revision ID: 0025
Revises: 0024
Create Date: 2026-05-28
"""

from alembic import op
import sqlalchemy as sa


revision = "0025"
down_revision = "0024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scan_runs",
        sa.Column("asset_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
    )
    op.add_column(
        "scan_runs",
        sa.Column("finding_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
    )

    # Best-effort backfill so historical runs keep their Activity-feed counts.
    # Guarded by to_regclass so the migration is idempotent if a partial drop
    # already happened (e.g. someone rolled back manually).
    op.execute("""
        UPDATE scan_runs
        SET asset_count = (
            SELECT COUNT(*) FROM assets WHERE assets.scan_run_id = scan_runs.id
        )
        WHERE to_regclass('public.assets') IS NOT NULL
    """)
    op.execute("""
        UPDATE scan_runs
        SET finding_count = (
            SELECT COUNT(*) FROM findings WHERE findings.scan_run_id = scan_runs.id
        )
        WHERE to_regclass('public.findings') IS NOT NULL
    """)

    # Drop the hypertables. TimescaleDB will tear down chunks + continuous
    # aggregates implicitly. Use IF EXISTS so re-runs after a partial drop
    # don't fail.
    op.execute("DROP TABLE IF EXISTS findings CASCADE")
    op.execute("DROP TABLE IF EXISTS assets CASCADE")


def downgrade() -> None:
    # The hypertables held observation data we can't reconstruct; downgrade
    # is best-effort. Restore an empty pair of regular tables so any
    # never-deployed readers don't crash; chunking would need to be re-enabled
    # manually in TimescaleDB.
    op.create_table(
        "assets",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("scan_run_id", sa.dialects.postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_runs.id"), nullable=False),
        sa.Column("asset_type", sa.Text(), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("parent_value", sa.Text(), nullable=True),
        sa.Column("metadata", sa.dialects.postgresql.JSONB(), nullable=True),
        sa.Column("ignored", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("tags", sa.dialects.postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'")),
        sa.PrimaryKeyConstraint("id", "discovered_at"),
    )
    op.create_table(
        "findings",
        sa.Column("id", sa.dialects.postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("scan_run_id", sa.dialects.postgresql.UUID(as_uuid=True), sa.ForeignKey("scan_runs.id"), nullable=False),
        sa.Column("asset_value", sa.Text(), nullable=False),
        sa.Column("finding_type", sa.Text(), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("detail", sa.dialects.postgresql.JSONB(), nullable=True),
        sa.Column("state", sa.Text(), nullable=False, server_default=sa.text("'open'")),
        sa.Column("acknowledged_by_id", sa.dialects.postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("suppressed_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("category", sa.Text(), nullable=True),
        sa.Column("cve_id", sa.Text(), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.Text(), nullable=True),
        sa.Column("cvss_version", sa.Text(), nullable=True),
        sa.Column("epss_score", sa.Float(), nullable=True),
        sa.Column("epss_percentile", sa.Float(), nullable=True),
        sa.Column("kev", sa.Boolean(), nullable=True),
        sa.Column("kev_date_added", sa.Date(), nullable=True),
        sa.Column("cwe", sa.Text(), nullable=True),
        sa.Column("tags", sa.dialects.postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'")),
        sa.PrimaryKeyConstraint("id", "discovered_at"),
    )

    op.drop_column("scan_runs", "finding_count")
    op.drop_column("scan_runs", "asset_count")
