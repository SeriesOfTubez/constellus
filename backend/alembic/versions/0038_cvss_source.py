"""Add cvss_source to findings_canonical.

`cvss_version` records *which* CVSS revision produced a score but not *who*
produced it. That was adequate while NVD reliably re-scored every CVE, so an
NVD-sourced score could be assumed. Since the April 2026 enrichment change,
NVD no longer routinely supplies severity when a CNA has already scored the
CVE, so a stored score may now originate from the CNA, from NVD, or from a
connector's own vendor feed — and nothing in the row distinguishes them.

That matters because scoring provenance is a trust signal: a CNA self-score
and an NVD analyst score are not interchangeable inputs. This mirrors the
existing `ssvc_source` column, which draws the same distinction for SSVC
(real CISA Vulnrichment vs a derived CVSS-vector fallback).

Nullable with no backfill — existing rows genuinely have unknown provenance
and must not be asserted as anything. Readers treat NULL as "unknown", never
as a default source.

Revision ID: 0038
Revises: 0037
Create Date: 2026-08-16
"""

from alembic import op
import sqlalchemy as sa


revision = "0038"
down_revision = "0037"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "findings_canonical",
        sa.Column("cvss_source", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("findings_canonical", "cvss_source")
