"""Allow multiple canonical rows per FQDN — one per (record_type, content)

The `assets_canonical.UNIQUE(asset_type, value)` constraint collapsed every
DNS record for a name into a single row, so an FQDN with A + AAAA + MX (or
just multiple A records via round-robin) lost all but one record in metadata.

The fix is two partial unique indexes:

  - dns_record rows are unique on (asset_type, value, record_type, content)
    so each distinct record gets its own canonical identity.
  - All other asset types keep (asset_type, value) — IP addresses, cloud
    resources, etc. have no record_type/content concept.

COALESCE on the JSONB fields collapses NULL/empty to '' inside the index so
pre-PG15 NULL-distinctness rules don't let bare CT-discovered rows (no
record_type yet) accumulate duplicates.

No data backfill is needed — existing rows are already unique under the new
key by virtue of having been unique under the old one.

Revision ID: 0026
Revises: 0025
Create Date: 2026-05-29
"""

from alembic import op
import sqlalchemy as sa


revision = "0026"
down_revision = "0025"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint(
        "uq_assets_canonical_type_value",
        "assets_canonical",
        type_="unique",
    )

    op.create_index(
        "uq_assets_canonical_dns",
        "assets_canonical",
        [
            "asset_type",
            "value",
            sa.text("coalesce(metadata->>'record_type', '')"),
            sa.text("coalesce(metadata->>'content', '')"),
        ],
        unique=True,
        postgresql_where=sa.text("asset_type = 'dns_record'"),
    )

    op.create_index(
        "uq_assets_canonical_non_dns",
        "assets_canonical",
        ["asset_type", "value"],
        unique=True,
        postgresql_where=sa.text("asset_type <> 'dns_record'"),
    )


def downgrade() -> None:
    op.drop_index("uq_assets_canonical_non_dns", table_name="assets_canonical")
    op.drop_index("uq_assets_canonical_dns", table_name="assets_canonical")
    op.create_unique_constraint(
        "uq_assets_canonical_type_value",
        "assets_canonical",
        ["asset_type", "value"],
    )
