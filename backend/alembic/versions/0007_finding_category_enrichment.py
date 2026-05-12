"""add category and enrichment columns to findings

Revision ID: 0007
Revises: 0006
Create Date: 2026-05-07
"""

from alembic import op
import sqlalchemy as sa

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("category", sa.String(50), nullable=True))
    op.add_column("findings", sa.Column("cve_id", sa.String(20), nullable=True))
    op.add_column("findings", sa.Column("cvss_score", sa.Float(), nullable=True))
    op.add_column("findings", sa.Column("cvss_vector", sa.String(100), nullable=True))
    op.add_column("findings", sa.Column("cvss_version", sa.String(5), nullable=True))
    op.add_column("findings", sa.Column("epss_score", sa.Float(), nullable=True))
    op.add_column("findings", sa.Column("epss_percentile", sa.Float(), nullable=True))
    op.add_column("findings", sa.Column("kev", sa.Boolean(), nullable=True))
    op.add_column("findings", sa.Column("kev_date_added", sa.Date(), nullable=True))
    op.add_column("findings", sa.Column("cwe", sa.String(20), nullable=True))
    op.create_index("ix_findings_category", "findings", ["category"])
    op.create_index("ix_findings_cve_id", "findings", ["cve_id"])


def downgrade() -> None:
    op.drop_index("ix_findings_cve_id", table_name="findings")
    op.drop_index("ix_findings_category", table_name="findings")
    for col in ["cwe", "kev_date_added", "kev", "epss_percentile", "epss_score",
                "cvss_version", "cvss_vector", "cvss_score", "cve_id", "category"]:
        op.drop_column("findings", col)
