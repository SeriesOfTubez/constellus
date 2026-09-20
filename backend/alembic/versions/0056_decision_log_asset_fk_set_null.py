"""Make authorisation_decisions.asset_canonical_id ON DELETE SET NULL (planning#195).

## The defect

`authorisation_decisions.asset_canonical_id` FKs to `assets_canonical.id`
with **NO ACTION** — the only child of `assets_canonical` that does not
cascade. Every sibling (`asset_claims`, `asset_state`,
`asset_hygiene_score`, `findings_canonical`, `target_asset_links`) is
`ON DELETE CASCADE`. So deleting any asset the probe-authorisation gate
has ever evaluated raises `ForeignKeyViolation` and the delete fails.
Measured on dev (2026-09-20): `confdeltype='a'`, and **all 4 assets in the
database are undeletable — 4 of 4**.

Three reachable paths hit this, none with a handler: `api/assets.py`'s
`delete_asset` (bare `db.delete()` -> unhandled `IntegrityError` -> HTTP
500) and `delete_assets_by_apex` (bulk delete, one gated asset fails the
whole batch), and `api/targets.py`'s `_soft_cascade_target_assets` (same
bulk shape, and it runs inside `bulk_delete_targets`/`delete_target`, so it
takes the surrounding target delete down with it too).

## The decision: SET NULL, not CASCADE, not "keep NO ACTION + handle it"

Decided by the maintainer (planning#195). Three options, two rejected:

  - **CASCADE** — silently shrinks `authorisation_decisions`. planning#189
    established that this table is READ to decide the planning#148
    `enforce` flip — its entire lesson was that this table's row counts get
    trusted as a measurement (see 0053's purge and the 87%-residue
    incident `_decision_log.py` documents). Making an ordinary user action
    (deleting an asset) quietly delete evidence from that table
    reintroduces exactly the failure planning#189 exists to prevent — a
    statistic computed over this table would change for a reason that has
    nothing to do with scanning.
  - **Keep NO ACTION, add an explicit error** — the set of gate-evaluated
    assets only ever grows (every asset Phase 1.5 hands to the gate earns
    a row), so over time nothing stays deletable. Dev is already at 4/4:
    every asset in the database, without exception, is currently
    undeletable. An audit trail that makes the estate immutable is not a
    working product; "delete this asset" needs to keep working forever,
    not just until the gate has seen everything.
  - **SET NULL (chosen)** — the decision row survives, loses only its
    reference. The row keeps existing for the `enforce`-flip count; the
    dangling pointer to a now-gone asset is exactly what nullable FKs with
    `ON DELETE SET NULL` exist to express.

## Why the column being already nullable makes this a no-op for existing
readers

`asset_canonical_id` has been nullable since this table's introduction
(`app/models/authorisation_decision.py`'s own docstring: "nullable because
a decision may be evaluated for an address before an AssetCanonical row
exists for it"), and planning#196 step 2's domain-scoped rows
(`authorise_discovery`) are *always* NULL-canonical — a domain being
enumerated has no canonical row to resolve to at all. So every reader of
this table already has to treat `asset_canonical_id IS NULL` as an
ordinary, expected state, not an anomaly. This migration adds exactly one
more way a row can arrive at a state every existing reader already
handles; it does not introduce a new NULL-handling burden anywhere.

## Measured finding: the residue shape this issue feared does not exist,
and `_unreachable` is deliberately left unchanged

`app/tests/_decision_log.py::_unreachable` defines residue as
`asset_canonical_id IS NULL` **AND** no `evidence_snapshot->>'scan_run_id'`.
The issue that requested this migration worried that SET NULL orphans
would start satisfying that predicate and get swept up as false residue.
Measured on dev: **all 92 rows carry a `scan_run_id`** (80 with a
canonical id, 12 without, zero without a run id). An orphaned REAL row
therefore still carries its `scan_run_id` after this migration runs — SET
NULL touches only `asset_canonical_id`, never `evidence_snapshot` — and
fails `_unreachable`'s second term exactly as it did before it was
orphaned. `_decision_log`'s own docstring already asserts "Real scan rows
always carry a run id"; this migration does not disturb that.

The guard in fact *gains* coverage, correctly: a test that writes a
decision row with no run id and then deletes its asset now creates
genuinely unreachable residue (NULL canonical id, still no run id), and
`test_zz_decision_log_hygiene.py` firing on that is the guard working, not
a false positive to fix.

Do **not** add a `decision_scope` term to `_unreachable` to try to
distinguish "orphaned by this migration" from "never resolved a canonical
row in the first place" — both measured findings above show there is
nothing for such a term to exclude: real orphaned rows already fail on
`scan_run_id` alone, and a term that excludes nothing is noise that
weakens the invariant for a future reader who assumes it must be pulling
its weight.

No data migration: no existing row needs rewriting, and this migration
writes none. It is the constraint change alone.

Revision ID: 0056
Revises: 0055
Create Date: 2026-09-20
"""

from alembic import op

revision = "0056"
down_revision = "0055"
branch_labels = None
depends_on = None

_FK_NAME = "authorisation_decisions_asset_canonical_id_fkey"


def upgrade() -> None:
    op.drop_constraint(_FK_NAME, "authorisation_decisions", type_="foreignkey")
    op.create_foreign_key(
        _FK_NAME,
        "authorisation_decisions",
        "assets_canonical",
        ["asset_canonical_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    # Reverses the constraint only. No row was rewritten by upgrade(), so
    # there is nothing to restore beyond the FK's delete rule — a row
    # orphaned under SET NULL stays orphaned on downgrade, same as it
    # would have if it had simply never resolved a canonical row.
    op.drop_constraint(_FK_NAME, "authorisation_decisions", type_="foreignkey")
    op.create_foreign_key(
        _FK_NAME,
        "authorisation_decisions",
        "assets_canonical",
        ["asset_canonical_id"],
        ["id"],
    )
