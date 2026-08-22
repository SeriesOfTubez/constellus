"""DROP assets_canonical.metadata — the end of the claims migration
(L3c-4, planning#144). IRREVERSIBLE IN PRACTICE.

The `metadata` JSONB blob was Constellus' de-facto current-state store: every
connector, prober and enricher shallow-merged its observations into one
untyped dict per asset, and every reader picked keys back out of it. It had
no per-observer attribution (so a claim could never be traced, aged or
retired), no schema, and accumulate-only merge semantics (so a signal that
disappeared never cleared).

L0–L3c replaced it:
  - L1 (0039)   asset_claims / claim_types / observers — per-observer grounding.
  - L2          claim_emitter decomposes each batch's observations into typed
                claims; projector folds them into asset_state.
  - L3a/L3b     the TTL caches, DNS identity (-> real columns, 0040) and the
                derived keys moved over.
  - L3c-1..3    every producer converted, every reader repointed, and the API
                serializer rebuilt onto `metadata_bridge` so the frontend
                contract survives this migration untouched.

This migration removes the column now that nothing reads or writes it.

REVERSIBILITY: `downgrade()` re-adds the column, but it CANNOT restore the
data — the values go with the drop. That is accepted by decision (this
deployment's asset data is disposable and rebuilt by the next scan), but it
means a downgrade past this point yields an EMPTY column, not the prior
state. A downgrade is only meaningful alongside a code rollback to <= L3c-3,
which would then refill it by rescanning.

Revision ID: 0043
Revises: 0042
Create Date: 2026-08-21
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


revision = "0043"
down_revision = "0042"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_column("assets_canonical", "metadata")


def downgrade() -> None:
    # Structure only — the data is NOT recoverable (see module docstring).
    op.add_column(
        "assets_canonical",
        sa.Column(
            "metadata",
            JSONB,
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
    )
