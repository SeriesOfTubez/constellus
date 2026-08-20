"""Promote dns_record identity (record_type/content) to real columns
(L3b-1, planning#144).

Migration 0026 keyed dns_record dedup/identity off a partial unique index
on `coalesce(metadata->>'record_type', ''), coalesce(metadata->>'content',
'')` — a JSONB path expression, not a column. That's a problem for planning
#144's eventual L3c cutover (dropping `assets_canonical.metadata` once
claims are fully authoritative): identity/dedup can't keep depending on the
JSONB blob that's slated for removal.

This migration promotes `record_type`/`content` to real
`assets_canonical` columns and repoints the unique index at them.
`asset_metadata` keeps carrying `record_type`/`content` unchanged (still
written by asset_writer, still what the API serializes for the frontend)
— dropping them from metadata is L3c's job, not this one. This slice only
changes who is AUTHORITATIVE for identity: the columns, not the JSONB path.

**The index swap is the risky part of this migration.** Ordering matters:

  1. Add the (nullable) columns.
  2. Backfill them from existing metadata for all dns_record rows —
     BEFORE touching the index. If the index were dropped/recreated first,
     there'd be a window where dns_record rows have no unique constraint
     at all, and (worse) the backfill UPDATE would need to satisfy the new
     column-based index against not-yet-populated columns.
  3. Only then swap `uq_assets_canonical_dns`: drop the metadata-path
     version, recreate it on the columns. This must be atomic with the
     backfill already complete, or a write landing between drop and
     create races an unconstrained window.

The COALESCE(...,'') wrapping is kept verbatim from 0026 — pre-PG15,
NULL is not equal to NULL for uniqueness purposes, so two bare
CT-discovered dns_record rows (no record_type/content yet) would collide
past the DB's own NULL-distinctness and accumulate duplicates without it.

`uq_assets_canonical_non_dns` (asset_type, value) is untouched — non-DNS
asset types have no record_type/content concept.

This migration does NOT touch `_defensive_insert_assets`'s ON CONFLICT
inference or `_canonical_key` — see asset_writer.py / claim_emitter.py in
the same commit, which must move in lockstep with this index or dns_record
inserts start raising IntegrityError instead of deduping.

Revision ID: 0040
Revises: 0039
Create Date: 2026-08-19
"""

from alembic import op
import sqlalchemy as sa


revision = "0040"
down_revision = "0039"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("assets_canonical", sa.Column("record_type", sa.Text(), nullable=True))
    op.add_column("assets_canonical", sa.Column("content", sa.Text(), nullable=True))

    # Backfill BEFORE the index swap — see module docstring for why the
    # ordering is load-bearing here.
    op.execute(
        "UPDATE assets_canonical "
        "SET record_type = metadata->>'record_type', content = metadata->>'content' "
        "WHERE asset_type = 'dns_record'"
    )

    op.drop_index("uq_assets_canonical_dns", table_name="assets_canonical")
    op.create_index(
        "uq_assets_canonical_dns",
        "assets_canonical",
        [
            "asset_type",
            "value",
            sa.text("coalesce(record_type, '')"),
            sa.text("coalesce(content, '')"),
        ],
        unique=True,
        postgresql_where=sa.text("asset_type = 'dns_record'"),
    )


def downgrade() -> None:
    op.drop_index("uq_assets_canonical_dns", table_name="assets_canonical")
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

    op.drop_column("assets_canonical", "content")
    op.drop_column("assets_canonical", "record_type")
