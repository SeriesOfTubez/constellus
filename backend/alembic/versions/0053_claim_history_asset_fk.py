"""Purge orphaned `claim_history` rows and make the orphaning structurally impossible (planning#191).

`claim_history` had **no foreign key at all**, while `asset_claims` — the
current-value table beside it — has had `ON DELETE CASCADE` to
`assets_canonical` since 0039. So deleting an asset took its claims with it
and stranded its history, silently: nothing errors and nothing references the
stranded rows. Measured on the dev DB on 2026-09-20, **4,808 of 4,827 rows
(99.6%) referenced an asset that no longer existed**, and every orphaned
claim_type's newest row was from that same day — live, not historical
residue.

Retention rule (decided by the maintainer, planning#191): **if an asset is
deleted, its `claim_history` goes with it.** A history row is per-asset
provenance — "observer X claimed value Y about asset Z at time T" — and it is
meaningless once Z is gone. Re-discovery mints a NEW `asset_canonical_id`, so
the old rows could never re-link to the returning asset even if kept.

An asset "going offline" does not delete it. Absence is *modelled*, never
deleted (planning#145; `_carry_forward_unclaimed_ports` and the prune's grace
windows exist precisely so a missed observation is not treated as gone).
There are exactly three code paths that delete an `assets_canonical` row and
all three are deliberate operator acts: the admin single-asset delete in
`api/assets.py`, `targets._soft_cascade_target_assets`, and
`_sweep_cname_descendants`. So "the asset vanished" and "an admin deleted the
asset" are not two cases needing to be told apart — in this codebase the
first one never deletes anything.

Declarative FK rather than an application-level cascade, deliberately: a
per-call-site delete is an opt-out list wearing a different hat, and it drifts
the moment someone adds a fourth delete path.

`score_history` / `hygiene_history` are NOT swept in
--------------------------------------------------
Same shape, different answer. Those feed org-level trend aggregates
(planning#121/#131), so cascading their rows away would silently rewrite last
month's estate-wide numbers when you clean up an asset today. That is a real
reason to keep rows and it does not transfer to `claim_history`, which is not
an aggregate input and which nothing currently reads. Changing them is a
separate decision with a trend-rewriting consequence to weigh; do not sweep
them in because they look alike.

The partition objection is measurably false on this stack
---------------------------------------------------------
`ClaimHistory`'s inherited rationale claimed an FK "would make a future
partition DROP/DETACH more expensive". Tested against the dev database
(PostgreSQL 18.6), in a rolled-back transaction: the FK is accepted on the
range-partitioned table; a parent `DELETE` cascades to rows in two different
partitions; `DETACH PARTITION` with the FK present succeeds; `DROP TABLE` on
the detached partition succeeds. The restriction people remember applies to
FKs *referencing* a partitioned table — this one points the other way. So
planning#131/#155's tiered retention is not blocked by it. The companion
docstring changes in this commit correct the claim rather than inherit it.

Whether retention's own partition drops should be reconciled with this rule —
the same table from the other end, deleting history whose asset still exists —
is planning#155's call, raised there.

Order matters: the purge must precede the constraint, or the ADD CONSTRAINT
validation fails on the 4,808 existing violations. The post-check below aborts
the whole migration (Alembic runs it in a transaction) if the delete took
anything it should not have — count-first / delete-second / verify-third, the
shape planning#189 settled on, because on this project the dev database IS the
test database and the surviving rows are irreplaceable.

Revision ID: 0053
Revises: 0052
Create Date: 2026-09-20
"""

from alembic import op
import sqlalchemy as sa

revision = "0053"
down_revision = "0052"
branch_labels = None
depends_on = None

_FK_NAME = "fk_claim_history_asset_canonical"

_ORPHANED = """
    NOT EXISTS (SELECT 1 FROM assets_canonical a WHERE a.id = h.asset_canonical_id)
"""


def upgrade() -> None:
    conn = op.get_bind()

    live_before = conn.execute(sa.text(f"""
        SELECT count(*) FROM claim_history h WHERE NOT ({_ORPHANED})
    """)).scalar_one()

    conn.execute(sa.text(f"DELETE FROM claim_history h WHERE {_ORPHANED}"))

    live_after, orphans_after = conn.execute(sa.text(f"""
        SELECT count(*) FILTER (WHERE NOT ({_ORPHANED})),
               count(*) FILTER (WHERE {_ORPHANED})
        FROM claim_history h
    """)).one()

    # Verify-third. Raising here rolls the migration back whole, so a purge
    # that took a live row can never be committed.
    if live_after != live_before or orphans_after != 0:
        raise RuntimeError(
            f"planning#191 purge refused: live rows {live_before} -> {live_after} "
            f"(must be unchanged), orphans remaining {orphans_after} (must be 0). "
            "Nothing was written."
        )

    op.create_foreign_key(
        _FK_NAME,
        "claim_history",
        "assets_canonical",
        ["asset_canonical_id"],
        ["id"],
        ondelete="CASCADE",
    )


def downgrade() -> None:
    # Only the constraint comes back off. The purged rows are not restorable
    # and are not worth restoring — they described assets that no longer
    # exist, which is the whole finding.
    op.drop_constraint(_FK_NAME, "claim_history", type_="foreignkey")
