"""Local CPE→CVE version-range index (native version→CVE matching, #66 B0).

A product-scoped mirror of NVD `cpeMatch` ranges for the D7 product set, so the
version matcher (chunk B) can resolve "installed version → affected CVEs +
fixed version" against a LOCAL table with no per-scan VulnCheck/NVD call.

Seeded from the free NVD 2.0 API (server-side CPE filter) and kept fresh by a
VulnCheck nist-nvd2 `lastMod` delta (vcConfigurations covers the NVD analysis
backlog). One row per vulnerable cpeMatch entry; refreshed by delete-by-cve +
re-insert, so no unique constraint is needed. Plain lookup table — not a
hypertable.

Revision ID: 0035
Revises: 0034
Create Date: 2026-06-20
"""

from alembic import op
import sqlalchemy as sa


revision = "0035"
down_revision = "0034"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cpe_cve_ranges",
        sa.Column("id", sa.BigInteger(), autoincrement=True, primary_key=True),
        sa.Column("cve_id", sa.Text(), nullable=False),
        # canonical NVD vendor:product (aliases folded in at ingest)
        sa.Column("vendor", sa.Text(), nullable=False),
        sa.Column("product", sa.Text(), nullable=False),
        # version range bounds (any/all may be NULL); version_end_excluding is
        # the fixed version when present (what #34 consumes)
        sa.Column("version_start_including", sa.Text(), nullable=True),
        sa.Column("version_start_excluding", sa.Text(), nullable=True),
        sa.Column("version_end_including", sa.Text(), nullable=True),
        sa.Column("version_end_excluding", sa.Text(), nullable=True),
        # concrete-version cpeMatch with no range (e.g. http_server:2.4.49)
        sa.Column("exact_version", sa.Text(), nullable=True),
        # cpeMatch with version '*' and no bounds → every version vulnerable
        sa.Column("all_versions", sa.Boolean(), nullable=False, server_default=sa.false()),
        # provenance: 'nvd' (seed) | 'vulncheck' (delta / vcConfigurations)
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("cpe_criteria", sa.Text(), nullable=True),
        sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_cpe_cve_ranges_cve_id", "cpe_cve_ranges", ["cve_id"])
    op.create_index(
        "ix_cpe_cve_ranges_vendor_product", "cpe_cve_ranges", ["vendor", "product"]
    )


def downgrade() -> None:
    op.drop_index("ix_cpe_cve_ranges_vendor_product", table_name="cpe_cve_ranges")
    op.drop_index("ix_cpe_cve_ranges_cve_id", table_name="cpe_cve_ranges")
    op.drop_table("cpe_cve_ranges")
