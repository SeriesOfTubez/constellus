"""Asset hygiene score — pre-computed skeleton table (planning#130, L1).

Constellus already has a per-FINDING score (Constellus Risk Score,
`risk_scorer.py`). This is the per-ASSET counterpart: "how well is this
individual machine being managed", independent of whether it currently has
an open finding. The two answer different questions and neither subsumes
the other — an asset can be hygiene-`critical` (unpatched EOL software,
never scanned, no ownership record) with zero open findings simply because
nothing has found the vulnerability yet, and that gap is exactly what this
score exists to surface.

Why a pre-computed table instead of a read-time view (the epic's stated
reason, carried here verbatim so a future editor doesn't "simplify" this
into a JOIN): at the deployment sizes this product targets (500k+ assets),
a read-time aggregation over `asset_claims` + `asset_state` per request is
a query-performance non-starter for any list/sort/filter view — "worst
assets first" is exactly a `score ASC` scan over an indexed column, not a
correlated subquery per row. Separately, pre-computed aggregations are also
the single largest accuracy lever for LLM-over-database question answering
against this schema: an agent asked "what are our worst-managed assets"
gets a materialized, indexed answer instead of having to reconstruct the
five-dimension scoring logic itself from raw claims on every query. Both
reasons point the same way: compute nightly (`hygiene_scorer.run`, wired
into the scheduler in this same commit), store one row per scored asset,
serve reads straight off this table.

This is a skeleton migration: the table, its CHECK-constrained vocabulary,
and its two sort/filter indexes. The scoring logic that populates it lives
in `app.services.hygiene_scorer`; see that module's docstring for the five
dimensions (coverage / health / currency / exposure / ownership) and the
settled "unknown ranks below bad" rule this whole table exists to encode.
`dimensions` is JSONB rather than five separate columns because each
dimension's shape (`grade`, `score`, `reason_codes`, `detail`) is uniform
and self-describing, and a 6th dimension is a known-likely future addition
(planning#137's `expected_stack` policy check) that a JSONB blob absorbs
without a migration; only `score` and `band` — the columns list/sort/filter
queries actually predicate on — get real columns and indexes. There is
deliberately NO per-key CHECK constraint validating the grade strings
inside `dimensions`: Postgres CHECK constraints can't reach into JSONB
structure without a much heavier `jsonb_path_exists` expression than the
rest of this codebase uses for JSONB columns (see `asset_state.attributes`,
`asset_claims.claim_value` — neither is structurally constrained either),
and the grade vocabulary is already enforced once, in application code, by
`hygiene_scorer.GRADE_SCORES`. `band` DOES get a real CHECK constraint
below because it is a real column with real query predicates
(`app/api/hygiene.py`'s band filter) that benefit from failing at the DB
boundary, not just the application boundary, on a bad value.

Revision ID: 0045
Revises: 0044
Create Date: 2026-08-22
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID


revision = "0045"
down_revision = "0044"
branch_labels = None
depends_on = None


# Mirrors app/models/asset_hygiene_score.py's BAND_VALUES (companion change,
# same commit). Adding a band means editing both, plus the CHECK below in a
# follow-up migration — same discipline as ESTATE_VALUES / CLAIM_TYPES.
BAND_VALUES = ("critical", "poor", "fair", "good", "excellent")


def upgrade() -> None:
    band_check = " OR ".join(f"band = '{v}'" for v in BAND_VALUES)

    op.create_table(
        "asset_hygiene_score",
        sa.Column(
            "asset_canonical_id", UUID(as_uuid=True),
            sa.ForeignKey("assets_canonical.id", ondelete="CASCADE"), primary_key=True,
        ),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("band", sa.Text(), nullable=False),
        sa.Column("dimensions", JSONB, nullable=False, server_default=sa.text("'{}'")),
        sa.Column("computed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("score >= 0 AND score <= 100", name="ck_asset_hygiene_score_score_range"),
        sa.CheckConstraint(band_check, name="ck_asset_hygiene_score_band"),
    )
    op.create_index("ix_asset_hygiene_score_score", "asset_hygiene_score", ["score"])
    op.create_index("ix_asset_hygiene_score_computed_at", "asset_hygiene_score", ["computed_at"])


def downgrade() -> None:
    op.drop_index("ix_asset_hygiene_score_computed_at", table_name="asset_hygiene_score")
    op.drop_index("ix_asset_hygiene_score_score", table_name="asset_hygiene_score")
    op.drop_table("asset_hygiene_score")
