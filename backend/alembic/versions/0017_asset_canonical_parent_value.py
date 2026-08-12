"""Add parent_value to assets_canonical

Discovery-time hint linking a child asset to its parent value (e.g. an
ip_address back to the dns_record it resolved from, or a dns_record to its
parent zone). This duplicates information that the resolves_to edges also
encode in graph form, but having it inline on the asset row keeps grouping
queries and tag-rule evaluations simple. Backfilled from the legacy `assets`
hypertable's parent_value where present.

Revision ID: 0017
Revises: 0016
Create Date: 2026-05-25
"""

from alembic import op
import sqlalchemy as sa


revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "assets_canonical",
        sa.Column("parent_value", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_assets_canonical_parent_value",
        "assets_canonical",
        ["parent_value"],
    )
    # Backfill from the latest legacy observation per (asset_type, value)
    op.execute("""
        UPDATE assets_canonical AS c
        SET parent_value = a.parent_value
        FROM (
            SELECT DISTINCT ON (asset_type, value)
                asset_type, value, parent_value
            FROM assets
            WHERE parent_value IS NOT NULL
            ORDER BY asset_type, value, discovered_at DESC
        ) AS a
        WHERE a.asset_type = c.asset_type
          AND a.value = c.value
    """)


def downgrade() -> None:
    op.drop_index("ix_assets_canonical_parent_value", table_name="assets_canonical")
    op.drop_column("assets_canonical", "parent_value")
